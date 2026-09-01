# MiniMax H3 人脸参考视频 1.0.1（预览）

这是可安装到 VGen Worker 的 Marketplace 包。输入人脸照片和原视频，H3 Ref2VA 重新生成约 5.17 秒视频，输出接回原视频对应片段的音轨。**不是逐帧人脸替换，不能保证背景、动作、口型或人脸身份完全不变。** 仅使用本人或获授权素材。

已验证包结构、参数映射与安全绑定；尚未做 GPU 真实素材出片验收。请先做短片测试，不要据此承诺商业效果。

## 运行前提

- VGen CLI 支持 `vgen task submit --video`，Worker 的 ComfyUI Executor 至少为 **1.3.0**。现有 VGen 0.13.31 / Executor 1.2.0 不支持此包，需要先发布并升级含视频输入支持的新版运行时。单独上架此包不会升级运行时。
- Gateway 需支持 Worker 上报 `v2v` 操作及 `Video Slice` 原生节点名；这部分与新版运行时一起部署。
- ComfyUI 至少 0.33.0。全图为原生节点，无额外 Node Pack。
- 预览调度门槛设为 24 GiB 显存、48 GiB 内存；这些是保守调度限制，不是实测性能保证，仍可能因设备或设置而内存不足。
- 4 个模型共 42,470,585,471 字节。已有 H3 的文本编码器和两个 VAE 可按 SHA-256 复用；新增 Ref2VA 主模型为 20,970,379,616 字节。
- 1.0.1 将 Ref2VA 主模型切换到 ModelScope 的固定提交；文件大小和 SHA-256 与上游 Comfy-Org 文件完全一致，改善国内 Worker 的下载可用性。
- 模型由 Worker 在显式执行安装命令后下载并校验。模型许可与工作流模板 MIT 许可不同，请审阅 [MiniMax H3 许可](https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE)。

## 从 Marketplace 安装

先使用已支持上述能力的新版 CLI/Worker。以下入口使用现有静态 Marketplace 的未签名预览机制；`--allow-unsigned` 与 `--approve-nodes` 是明确的信任审批，不代表签名或效果验收。

```bash
vgen workflow search minimax-h3-face-reference --index https://vgen.zcbiz.com/marketplace/index.json

vgen workflow install https://vgen.zcbiz.com/marketplace/workflows/vgen/minimax-h3-face-reference/1.0.1/workflow.zip --allow-unsigned

vgen broker workflow-install vgen/minimax-h3-face-reference@1.0.1 --worker "HONEYLONG GPU Worker" --approve-nodes --allow-unsigned --wait
```

将 Worker 名称换成自己的设备。工作流引用和模型摘要均由包固定，不会修改旧 H3 工作流或复用不兼容的 FL2VA 权重。

## 准备原视频

选取至少 5.25 秒的单人镜头。H3 参考帧按 **24 fps** 读取，必须先转换；CLI 的 `--video` 负责加密上传，不会擅自改变视频帧率。

下面从开头截取一段，保留音轨内容；`-n` 保证不覆盖已有文件。该转换可能重编码音频，不保证音频字节原样保留。

```bash
ffmpeg -n -ss 0 -i original.mp4 -t 5.25 -map 0:v:0 -map '0:a:0?' -vf "fps=24,scale=1280:1280:force_original_aspect_ratio=decrease:force_divisible_by=2,setsar=1" -c:v libx264 -crf 18 -pix_fmt yuv420p -c:a aac -b:a 192k reference_24fps.mp4
```

准备清晰、无遮挡的单人脸照片 `face.png`。视频不足 124/24 秒时，图中的截取节点会报错，不会静默补帧。

## 预检和提交

把素材路径换成自己的本地文件。`--image` 和 `--video` 会经过端到端加密素材通道；不要用 `-p video=...` 传路径，也不要填写 Worker 上已有文件路径。

```bash
vgen task preflight --workflow vgen/minimax-h3-face-reference@1.0.1 --image ./face.png --video ./reference_24fps.mp4

vgen task submit "Use <Picture 1> only for facial identity. Re-create the single-person shot in <Video 1>, retaining its clothing, hairstyle, lighting, background, camera motion, body movement and timing. Keep the same facial identity throughout. Do not add people, cuts, captions or new dialogue." --workflow vgen/minimax-h3-face-reference@1.0.1 --image ./face.png --video ./reference_24fps.mp4 --wait --output-dir ./h3-face-output
```

默认竖屏 480×832、124 帧、24 fps、20 步。横屏加 `-p width=832 -p height=480`；提高画质可用 `-p width=768 -p height=1344` 或反向横屏。只支持这四组尺寸，避免意外创建过大任务。`-p seed=1234` 固定种子；`-p ref_image_size=max` 会增加参考计算量。

可用参数：`prompt`、`image`、`video`、`seed`、`steps`（20–30）、`width`、`height`、`start_time`（原视频中截取起点，秒）、`ref_image_size`。输出时长固定，避免参考片段与音轨时长分离。

预检只验证调度条件，不探测本地视频帧率，也不预留 Worker。首次出片后需人工检查脸部一致性、遮挡和侧脸、原音轨与新口型同步。

## 开发与发布

仓库目录包含 manifest、mapping、API graph、模型固定版本/大小/SHA-256 及包内校验和。没有把模型大文件放进工作流 ZIP。

```bash
vgen workflow package workflows/vgen/minimax-h3-face-reference/1.0.1 dist/minimax-h3-face-reference-1.0.1.zip
```

`workflow package` 仅生成 ZIP，`workflow publish` 也不负责上传服务器。上架需要上传 ZIP 至版本目录，并原子更新 Marketplace 的 `index.json`。同一个 id/version 不允许覆盖不同摘要；后续修改必须发布新版本。

改编自 [ComfyUI 官方 R2V 模板](https://github.com/Comfy-Org/workflow_templates/blob/d3b4a9e89573162b005961865164c18c8ae2206b/templates/video_minimax_h3_r2v.json)，模板版本为 `d3b4a9e89573162b005961865164c18c8ae2206b`；节点定义按 ComfyUI `v0.33.0` 与提交 `8a33128f2f8c5585c57486c07de481241e70a39c` 核对。

## 完整参考提示词

```text
<Picture 1> supplies only the facial identity of the adult person in the output. <Video 1> supplies the single person's body movement, head poses, expressions, clothing, hairstyle, camera movement, lighting, scene layout and action timing.

integrated_multimodal_description: Re-create the continuous single-person shot in <Video 1>, replacing the visible person's facial identity with the adult face in <Picture 1>. Maintain that same facial identity consistently through turns, expression changes and temporary occlusions. Retain the video's original clothing, hairstyle, body proportions, scene, camera framing and sequence of actions as closely as possible. Do not copy the portrait's background or clothing. Match facial lighting, perspective, skin texture and shadows to the video. Keep natural blinking and the visible timing of speech and expression. No face morphing, extra people, added scene cuts, captions or overlays.

overall_soundscape: Follow the reference shot's timing. Do not introduce new dialogue or music.
```

## 上游模板许可

```text
MIT License

Copyright (c) 2023-present Comfy Org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
