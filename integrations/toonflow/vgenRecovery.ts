/** Original VGen integration: persist correlation and restore completed videos after restart. */
import crypto from "node:crypto";
import fs from "node:fs";
import { LocalQueue } from "@/utils/vgenLocal";
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

export function generateVgenVideo(input: any, model: any): Promise<string> {
  return localQueue().generate(input, model);
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
    if (job.state === "succeeded") {
      await u.oss.writeFile(video.filePath!, fs.readFileSync(job.result).toString("base64"));
      await query().update({ state: "生成成功", errorReason: null });
    } else if (["failed", "cancelled", "needs_attention"].includes(job.state)) {
      await query().update({ state: "生成失败", errorReason: job.error || "任务已取消" });
    }
  }
}

export function startVgenRecovery() {
  if (timer) return;
  localQueue().start();
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
