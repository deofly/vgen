# 单人视频逐帧换脸 2.0.0

`h3-face` 2.0.0 不再让 MiniMax H3 重新生成整段画面。它保留原视频帧和原音轨，只在检测到的单个人脸椭圆内，将授权照片的人脸纹理和部分脸型逐帧贴合到原人物表情上。

因此，衣服、发型、身体动作、手机、背景、灯光、镜头运动和对白时间均来自原视频；没有检测到可信人脸的帧会原样通过，不会把上一帧的人脸硬贴上去。只可使用本人或已经获得明确授权的照片和视频。

## 与 1.x 的区别

- 1.x 是 H3 Ref2VA 生成式参考视频，可能重画人物和背景，也不保证身份替换明显。
- 2.0.0 是确定性的逐帧单脸替换，不使用 H3 大模型，不需要 42 GB H3 权重，也没有随机采样。
- `-p seed=...` 仍可保留在旧命令里，但仅为兼容，不影响结果。
- 当前仍沿用经过审查的 124 帧、24 fps 输入适配，因此一次输出约 5.17 秒；源文件不会被覆盖。

## 运行依赖

- VGen Worker 0.14.3 或更新版本，ComfyUI Executor 1.3.0 或更新版本。
- `VGen Temporal Face Swap` Node Pack 1.0.0。Node Pack 固定了 Windows CPython 3.11 的 MediaPipe 0.10.21、OpenCV 4.11.0.86 及其离线依赖。
- Google MediaPipe `face_landmarker.task` 固定到 SHA-256 `64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff`，许可证为 Apache-2.0。
- 节点在 Worker 本地处理，不把人脸素材发送给第三方换脸 API。

## 安装

```bash
vgen workflow install https://vgen.zcbiz.com/marketplace/workflows/vgen/minimax-h3-face-reference/2.0.0/workflow.zip --allow-unsigned

vgen broker workflow-install vgen/minimax-h3-face-reference@2.0.0 --worker "HONEYLONG GPU Worker" --approve-nodes --allow-unsigned --wait
```

首次安装会下载约 3.6 MB 的人脸关键点模型，并安装约 103 MB 的离线 Node Pack。安装过程会暂停并重启该 Worker 的 ComfyUI。

## 提交

可以直接沿用原命令；`--video-fps-mode auto` 会创建临时的 24 fps 提交副本，原视频不变。

```bash
vgen task submit \
  "Use <Picture 1> only for facial identity. Replace the single visible face in <Video 1>; retain the original clothing, hairstyle, lighting, background, camera motion, body movement, dialogue and timing." \
  --workflow h3-face@2.0.0 \
  --image ./face.png \
  --video ./original.mp4 \
  --video-fps-mode auto \
  -p seed=1234 \
  --wait \
  --output-dir ./h3-face-output
```

可调参数：

- `strength`：替换强度，默认 `1.0`。
- `identity_shape`：保留来源脸型比例的程度，默认 `0.3`，侧脸不稳时可降到 `0.15`。
- `feather`：脸部边缘羽化宽度，默认 `0.045`。
- `start_time`：从原视频的哪一秒开始截取。

清晰、接近正脸、无遮挡的来源照片效果最好。大角度侧脸、快速遮挡、多人画面和极低分辨率人脸仍可能出现贴合误差；本工作流明确只支持单人镜头。

## 开发打包

```bash
vgen workflow package workflows/vgen/minimax-h3-face-reference/2.0.0 dist/minimax-h3-face-reference-2.0.0.zip
```

工作流版本不可覆盖。Node Pack、模型和工作流包均以 SHA-256 固定；后续任何字节变化都必须发布新版本。
