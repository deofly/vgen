/** Direct CLI execution and a durable queue. No local HTTP service or shared secret. */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
// Toonflow already ships this native dependency; its upstream tree has no TS declarations.
const Database = require("better-sqlite3");

const terminal = new Set(["succeeded", "failed", "cancelled", "needs_attention"]);
export type Runner = (args: string[]) => Promise<any>;

export function cliExecutable(): string {
  if (process.env.VGEN_CLI) {
    if (!path.isAbsolute(process.env.VGEN_CLI)) throw new Error("VGEN_CLI 必须是可执行文件的绝对路径");
    return process.env.VGEN_CLI;
  }
  const installed = path.join(os.homedir(), ".local", "bin", "vgen");
  return fs.existsSync(installed) ? installed : "vgen";
}

export function runVgenCLI(args: string[], selectedProfile = process.env.VGEN_PROFILE): Promise<any> {
  const profile = args[0] === "task" && selectedProfile ? [`--profile=${selectedProfile}`] : [];
  return new Promise((resolve, reject) => {
    execFile(cliExecutable(), [args[0], ...profile, ...args.slice(1)], {
      shell: false, timeout: 600000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error) {
        if ((error as any).code === "ENOENT") return reject(new Error("未找到 VGen CLI，请先安装 VGen。"));
        const code = stderr.match(/\b(\d{6} [A-Z][A-Z0-9_]+):/)?.[1];
        return reject(new Error(code ? `VGen 调用失败：${code}` : "VGen 调用中断，请检查本机登录和网络。"));
      }
      try {
        const result = JSON.parse(stdout);
        if (!result || typeof result !== "object") throw new Error();
        resolve(result);
      } catch { reject(new Error("VGen 返回了无效的 JSON。")); }
    });
  });
}

export function runCLI(args: string[], selectedProfile = process.env.VGEN_PROFILE): Promise<any> {
  return runVgenCLI(["task", ...args], selectedProfile);
}

export function normalize(config: any, model: any) {
  const mode = Array.isArray(config.mode) && config.mode.length === 1 ? config.mode[0] : config.mode;
  const refs = config.referenceList || [];
  const counts: Record<string, number[]> = { text: [0], singleImage: [1], startEndRequired: [2], endFrameOptional: [1, 2], videoReference: [1, 2] };
  const workflowRef = model.workflowRef || "vgen/minimax-h3-8step@1.0.1";
  const h3 = workflowRef === "vgen/minimax-h3-8step@1.0.1";
  const allowedDurations = model.durationResolutionMap?.flatMap((item: any) => item.duration) || [1.625];
  if (!workflowRef.includes("@") || (h3 && config.duration !== 1.625) || !allowedDurations.includes(config.duration) ||
      (h3 && config.resolution !== "768p") || !["16:9", "9:16"].includes(config.aspectRatio) || (model.audio !== false && config.audio === false) ||
      typeof config.prompt !== "string" || !config.prompt.trim() || config.prompt.length > 20000 ||
      !Array.isArray(refs) || !counts[mode]?.includes(refs.length)) {
    throw new Error("生成参数不受支持，请使用当前工作流显示的参数。");
  }
  const images = refs.map((item: any) => {
    if (!['image', 'video'].includes(item.type) || typeof item.base64 !== "string") throw new Error("仅支持参考图片或视频。");
    const raw = item.base64.replace(/^data:[^;]+;base64,/, "");
    if (raw.length > (item.type === "video" ? 140 * 1024 * 1024 : 14 * 1024 * 1024) || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) throw new Error("素材编码无效或过大。");
    const bytes = Buffer.from(raw, "base64");
    if (bytes.toString("base64") !== raw || !bytes.length || bytes.length > (item.type === "video" ? 100 * 1024 * 1024 : 10 * 1024 * 1024)) throw new Error("素材编码无效或过大。");
    if (item.type === "video" && bytes.toString("ascii", 4, 8) !== "ftyp") throw new Error("参考视频必须是 MP4。");
    const extension = item.type === "video" ? ".mp4" : bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])) ? ".png" :
      bytes.subarray(0, 3).equals(Buffer.from([255,216,255])) ? ".jpg" :
      bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP" ? ".webp" : null;
    if (!extension) throw new Error("仅支持 PNG、JPEG、WebP 图片。");
    return { base64: raw, extension, type: item.type };
  });
  if (mode === "videoReference" && images.filter((item: any) => item.type === "video").length !== 1) {
    throw new Error("视频参考模式需要一条视频和可选的参考图片。");
  }
  const context = config.vgenContext || {};
  const requestId = config.vgenRequestId || crypto.randomUUID();
  if (!/^[A-Za-z0-9:_-]{1,160}$/.test(requestId)) throw new Error("无效的任务关联编号。");
  const defaults = model.parameterDefaults || {};
  const parameters = { ...defaults, prompt: config.prompt };
  if (Object.hasOwn(defaults, "width") && Object.hasOwn(defaults, "height")) {
    const portrait = Number(defaults.height) > Number(defaults.width);
    if (config.aspectRatio === "9:16" !== portrait) {
      parameters.width = defaults.height;
      parameters.height = defaults.width;
    }
  }
  if (Object.hasOwn(defaults, "frames") && Object.hasOwn(defaults, "fps")) {
    parameters.frames = Math.max(1, Math.round(config.duration * Number(defaults.fps)));
  }
  return { requestId, prompt: config.prompt, mode, aspectRatio: config.aspectRatio, images,
    workflowRef, workflowDigest: model.workflowDigest || null, parameters,
    context: { instance_id: context.instance_id, project_id: context.project_id,
      script_id: context.script_id, video_id: context.video_id,
      profile: process.env.VGEN_PROFILE || null } };
}

export class LocalQueue {
  private db: any;
  private busy = false;
  private closing = false;
  private timer?: ReturnType<typeof setInterval>;
  private run: Runner;
  constructor(readonly root: string, run?: Runner, readonly profile = process.env.VGEN_PROFILE || null) {
    this.run = run || (args => runCLI(args, this.profile || undefined));
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    fs.chmodSync(root, 0o700);
    this.db = new Database(path.join(root, "jobs.sqlite"));
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`CREATE TABLE IF NOT EXISTS owner (id INTEGER PRIMARY KEY, pid INTEGER);
      CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, request_id TEXT UNIQUE,
      digest TEXT, request TEXT, state TEXT, task_id TEXT, error TEXT, result TEXT,
      progress TEXT, created INTEGER, updated INTEGER)`);
    try { this.db.exec("ALTER TABLE jobs ADD COLUMN progress TEXT"); } catch { /* already present */ }
    try {
      this.db.transaction(() => {
        const owner = this.db.prepare("SELECT pid FROM owner WHERE id=1").get();
        if (owner?.pid) {
          let alive = true;
          try { process.kill(owner.pid, 0); } catch (error: any) { if (error.code === "ESRCH") alive = false; }
          if (alive) throw new Error("已有 Toonflow 实例在使用本地生成队列。");
        }
        this.db.prepare("INSERT OR REPLACE INTO owner VALUES(1,?)").run(process.pid);
        this.db.prepare("UPDATE jobs SET state='queued' WHERE state='checking'").run();
        this.db.prepare("UPDATE jobs SET state='needs_attention',error=? WHERE state='submitting'")
          .run("提交结果待核对，不会自动重复提交。请用 vgen task list 核对远端任务。");
      }).immediate();
    } catch (error) { this.db.close(); throw error; }
    fs.chmodSync(path.join(root, "jobs.sqlite"), 0o600);
  }
  start() {
    if (!this.timer) {
      this.timer = setInterval(() => { void this.tick(); }, 2000);
      this.timer.unref();
    }
  }
  async close() {
    this.closing = true;
    if (this.timer) clearInterval(this.timer);
    while (this.busy) await new Promise(resolve => setTimeout(resolve, 50));
    this.db.prepare("UPDATE owner SET pid=0 WHERE id=1 AND pid=?").run(process.pid);
    this.db.close();
  }
  rows(): any[] { return this.db.prepare("SELECT * FROM jobs ORDER BY created ASC").all(); }
  get(id: string): any { return this.db.prepare("SELECT * FROM jobs WHERE id=?").get(id); }
  async cancelRemote(taskId: string) { return this.run(["cancel", taskId]); }
  retry(id: string) {
    const row = this.get(id);
    if (!row || !["failed", "cancelled"].includes(row.state)) return null;
    const request = JSON.parse(row.request);
    const requestId = `${request.requestId}:retry:${crypto.randomUUID().slice(0, 12)}`;
    const retryId = crypto.randomUUID();
    const now = Date.now();
    this.db.prepare("INSERT INTO jobs(id,request_id,digest,request,state,created,updated) VALUES(?,?,?,?,?,?,?)")
      .run(retryId, requestId, row.digest, JSON.stringify({ ...request, requestId }), "queued", now, now);
    return this.get(retryId);
  }
  update(id: string, fields: Record<string, any>) {
    const values = { ...fields, updated: Date.now() };
    this.db.prepare(`UPDATE jobs SET ${Object.keys(values).map(key => `${key}=?`).join(",")} WHERE id=?`)
      .run(...Object.values(values), id);
  }
  add(config: any, model: any) {
    const request = normalize(config, model);
    request.context.profile = this.profile;
    const raw = JSON.stringify(request);
    const digest = crypto.createHash("sha256").update(raw).digest("hex");
    return this.db.transaction(() => {
      const existing = this.db.prepare("SELECT * FROM jobs WHERE request_id=?").get(request.requestId);
      if (existing) {
        if (existing.digest !== digest) throw new Error("同一视频任务编号不能用于不同内容。");
        return existing;
      }
      if (this.rows().filter(row => !terminal.has(row.state)).length >= 100) throw new Error("本地生成队列已满。");
      const id = crypto.randomUUID();
      this.db.prepare("INSERT INTO jobs(id,request_id,digest,request,state,created,updated) VALUES(?,?,?,?,?,?,?)")
        .run(id, request.requestId, digest, raw, "queued", Date.now(), Date.now());
      return this.get(id);
    })();
  }
  args(row: any) {
    const request = JSON.parse(row.request);
    const directory = path.join(this.root, row.id);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const [width, height] = request.aspectRatio === "16:9" ? [1344, 768] : [768, 1344];
    const parameters = { ...request.parameters };
    const h3 = request.workflowRef === "vgen/minimax-h3-8step@1.0.1";
    if (h3 && !Object.hasOwn(parameters, "width")) parameters.width = width;
    if (h3 && !Object.hasOwn(parameters, "height")) parameters.height = height;
    if (h3 && !Object.hasOwn(parameters, "frames")) parameters.frames = 39;
    if (h3 && !Object.hasOwn(parameters, "fps")) parameters.fps = 24;
    delete parameters.prompt;
    const args = [`--workflow=${request.workflowRef}`];
    for (const [key, value] of Object.entries(parameters)) {
      if (["image", "last_image", "video"].includes(key) || value === undefined || value === null) continue;
      args.push(`--parameter=${key}=${typeof value === "string" ? value : JSON.stringify(value)}`);
    }
    request.images.forEach((image: any, index: number) => {
      const file = path.join(directory, `input-${index}${image.extension}`);
      fs.writeFileSync(file, Buffer.from(image.base64, "base64"), { mode: 0o600 });
      const imageIndex = request.images.slice(0, index).filter((item: any) => item.type === "image").length;
      args.push(`--${image.type === "video" ? "video" : imageIndex === 0 ? "image" : "last-image"}=${file}`);
    });
    return [...args, "--", request.prompt];
  }
  async tick() {
    if (this.busy || this.closing) return;
    this.busy = true;
    let row: any;
    try {
      row = this.rows().find(item => !terminal.has(item.state));
      if (!row) return;
      if (row.state === "queued") {
        this.update(row.id, { state: "checking", error: null });
        const args = this.args(row);
        if (row.request && JSON.parse(row.request).workflowDigest) {
          const current = await runVgenCLI(["workflow", "show", JSON.parse(row.request).workflowRef, "--format=json"]);
          if (current.digest !== JSON.parse(row.request).workflowDigest) {
            this.update(row.id, { state: "failed", error: "工作流文件摘要已变化，已阻止提交。" });
            return;
          }
        }
        const checked = await this.run(["preflight", ...args]);
        if (!["ready", "queue_available"].includes(checked.state)) {
          const messages: Record<string, string> = {
            worker_offline_or_busy: "生成电脑当前离线、维护中或已满载，请启动 VGen Worker 后重试。",
            capability_mismatch: "生成电脑尚未准备好所需的模型或运行环境。",
            no_allocated_worker: "当前资源池没有已分配的生成电脑。",
            rate_not_approved: "使用费率尚未审批，请联系工作区管理员。",
            queue_full: "生成队列已满，请稍后重试。",
          };
          this.update(row.id, { state: "failed", error: messages[checked.state] || "生成条件未满足，请检查 VGen 配置。" });
          return;
        }
        if (this.closing) { this.update(row.id, { state: "queued" }); return; }
        this.update(row.id, { state: "submitting" });
        const task = await this.run(["submit", `--idempotency-key=toonflow:${row.id}`, ...args]);
        if (!/^tsk_[A-Za-z0-9]{1,156}$/.test(task.id || "")) throw new Error("提交结果缺少任务编号。");
        this.update(row.id, { state: "submitted", task_id: task.id, error: null });
        return;
      }
      const task = await this.run(["show", row.task_id, "--format=json"]);
      const attempts = Array.isArray(task.attempts) ? task.attempts : [];
      const latest = attempts.slice().reverse().find((item: any) => item && item.progress);
      if (latest) {
        const progress = typeof latest.progress === "string" ? latest.progress : JSON.stringify(latest.progress);
        this.update(row.id, { progress });
      }
      if (["failed", "cancelled", "expired"].includes(task.state)) {
        this.update(row.id, { state: task.state === "cancelled" ? "cancelled" : "failed", error: "VGen 任务已失败、取消或过期。" });
      } else if (task.state === "succeeded") {
        this.update(row.id, { state: "downloading", error: null });
        const output = path.join(this.root, row.id, "output");
        const downloaded = await this.run(["get", row.task_id, `--output-dir=${output}`, "--overwrite"]);
        const paths = (downloaded.outputs || []).map((item: any) => path.resolve(item.path));
        const videos = paths.filter((file: string) => file.startsWith(output + path.sep) &&
          file.toLowerCase().endsWith(".mp4") && fs.existsSync(file) && fs.lstatSync(file).isFile() &&
          fs.realpathSync(file).startsWith(fs.realpathSync(output) + path.sep));
        if (videos.length !== 1) { this.update(row.id, { state: "failed", error: "生成结果必须包含一个 MP4 视频。" }); return; }
        fs.chmodSync(videos[0], 0o600);
        this.update(row.id, { state: "succeeded", result: videos[0], error: null });
      } else this.update(row.id, { state: "running", error: null });
    } catch (error: any) {
      if (row) {
        const current = this.get(row.id);
        this.update(row.id, { state: current.state === "submitting" ? "needs_attention" : current.task_id ? current.state : "failed",
          error: current.state === "submitting" ? "提交结果待核对，不会自动重复提交。" : error.message || "VGen 本地处理失败。" });
      }
    } finally { this.busy = false; }
  }
  async generate(config: any, model: any): Promise<string> {
    const job = this.add(config, model);
    this.start();
    void this.tick();
    const deadline = Date.now() + 24 * 60 * 60 * 1000;
    while (!this.closing && Date.now() < deadline) {
      const row = this.get(job.id);
      if (row.state === "succeeded") return fs.readFileSync(row.result).toString("base64");
      if (terminal.has(row.state)) throw new Error(row.error || "生成任务已取消。");
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw new Error("等待已结束，已提交的视频将在下次启动后继续回流。");
  }
}
