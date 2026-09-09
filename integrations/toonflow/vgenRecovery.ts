/** Original VGen integration: persist correlation and restore completed videos after restart. */
import crypto from "node:crypto";
import fs from "node:fs";
import { LocalQueue, runVgenCLI } from "@/utils/vgenLocal";
import u from "@/utils";

const instanceId = () => crypto.createHash("sha256").update(u.getPath()).digest("hex").slice(0, 24);

export function vgenContext(input: any, record?: { relatedObjects: string; projectId: number }) {
  if (!record) return input;
  let context: any;
  try { context = JSON.parse(record.relatedObjects); } catch { return input; }
  if (!Number.isInteger(context.videoId) || !Number.isInteger(context.scriptId)) return input;
  return { ...input,
    vgenRequestId: `${instanceId()}:video:${context.videoId}`,
    vgenContext: { instance_id: instanceId(), project_id: record.projectId,
      script_id: context.scriptId, video_id: context.videoId },
  };
}

let queue: LocalQueue | undefined;
let timer: ReturnType<typeof setInterval> | undefined;
const localQueue = () => queue ??= new LocalQueue(u.getPath("vgen"));

/** Refresh the Toonflow model picker from immutable workflows installed for this CLI. */
export async function syncVgenWorkflows() {
  const listed = await runVgenCLI(["workflow", "list", "--format=json"]);
  if (!Array.isArray(listed)) return;
  const models: any[] = [];
  for (const item of listed) {
    if (!item?.id || !item.version || !item.digest) continue;
    const ref = `${item.id}@${item.version}`;
    const detail = await runVgenCLI(["workflow", "show", ref, "--format=json"]);
    const manifest = detail.manifest;
    const variant = manifest?.variants?.find((value: any) => value.executor_type === "comfyui");
    if (!variant || !variant.operations?.some((op: string) => ["t2v", "i2v", "flf", "v2v"].includes(op))) continue;
    const properties = manifest.parameters?.properties || {};
    const defaults: Record<string, any> = {};
    for (const [key, definition] of Object.entries<any>(properties)) {
      if (definition && Object.hasOwn(definition, "default")) defaults[key] = definition.default;
    }
    const fps = Number(defaults.fps || 24);
    const frames = Number(defaults.frames || 39);
    const duration = Object.hasOwn(defaults, "frames") && Object.hasOwn(defaults, "fps")
      ? Math.round((frames / fps) * 1000) / 1000
      : variant.operations.includes("v2v") ? 5.167 : 1.625;
    const modes = [];
    if (variant.operations.includes("t2v")) modes.push("text");
    if (variant.operations.includes("i2v")) modes.push("singleImage");
    if (variant.operations.includes("flf")) modes.push("endFrameOptional", "startEndRequired");
    if (variant.operations.includes("v2v")) modes.push("videoReference");
    models.push({
      name: `${manifest.title || item.id} · ${item.version}`,
      modelName: ref, type: "video", mode: modes,
      audio: variant.operations.includes("v2v") ? false : true,
      durationResolutionMap: [{ duration: [duration], resolution: ["default"] }],
      workflowRef: ref, workflowDigest: detail.digest,
      parameterDefaults: defaults,
    });
  }
  await u.db("o_vendorConfig").where("id", "vgen").update({ models: JSON.stringify(models) });
}

export function generateVgenVideo(input: any, model: any): Promise<string> {
  return localQueue().generate(input, model);
}

export async function cancelVgenVideo(videoId: number): Promise<boolean> {
  const item = localQueue().rows().find((job: any) => {
    try { return JSON.parse(job.request).context?.video_id === videoId; } catch { return false; }
  });
  if (!item || ["succeeded", "failed", "cancelled", "needs_attention"].includes(item.state)) return false;
  if (item.task_id) await localQueue().cancelRemote(item.task_id);
  localQueue().update(item.id, { state: "cancelled", error: "已取消" });
  return true;
}

export function retryVgenVideo(videoId: number): boolean {
  const item = localQueue().rows().find((job: any) => {
    try { return JSON.parse(job.request).context?.video_id === videoId; } catch { return false; }
  });
  if (!item || !localQueue().retry(item.id)) return false;
  localQueue().start();
  return true;
}

export async function recoverVgenVideos() {
  const jobs = localQueue().rows();
  for (const job of jobs) {
    const context = JSON.parse(job.request).context;
    if (context?.instance_id !== instanceId() || !Number.isInteger(context.video_id)) continue;
    const query = () => u.db("o_video").where({ id: context.video_id,
      projectId: context.project_id, scriptId: context.script_id });
    const video = await query().first();
    if (!video || video.state === "生成成功") continue;
    if (job.progress && (video as any).vgenProgress !== job.progress) {
      await (query() as any).update({ vgenProgress: job.progress });
    }
    if (job.state === "succeeded") {
      await u.oss.writeFile(video.filePath!, fs.readFileSync(job.result).toString("base64"));
      await (query() as any).update({ state: "生成成功", errorReason: null, vgenProgress: null });
    } else if (["failed", "cancelled", "needs_attention"].includes(job.state)) {
      await (query() as any).update({ state: "生成失败", errorReason: job.error || "任务已取消", vgenProgress: null });
    }
  }
}

export function startVgenRecovery() {
  if (timer) return;
  localQueue().start();
  void syncVgenWorkflows().catch(() => undefined);
  let busy = false;
  timer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try { await recoverVgenVideos(); }
    catch { /* Retry local recovery without exposing task content. */ }
    finally { busy = false; }
  }, 5000);
  timer.unref();
}

export async function stopVgenRecovery() {
  if (timer) clearInterval(timer);
  timer = undefined;
  if (queue) await queue.close();
  queue = undefined;
}
