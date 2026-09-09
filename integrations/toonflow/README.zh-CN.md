# Toonflow × VGen：直接调用 CLI

[English](README.md) | 简体中文

Toonflow 后端直接调用本机 `vgen` 命令，复用现有登录、默认工作区和资源池。
不需要额外的桥接服务，也不需要填写本地连接地址或密钥。
文字、图片生成继续使用 Toonflow 的其他供应商。

## 启动

先确认本机已安装并完成 VGen 接入：

```bash
vgen profile show
vgen task preflight --workflow=vgen/minimax-h3-8step@1.0.1
```

刚通过工作区审批时先执行 `vgen join --resume`。
在 VGen 源码目录安装集成：

```bash
python3 integrations/toonflow/install.py /path/to/Toonflow-app
```

然后在 Toonflow-app 源码目录启动：

```bash
yarn install --frozen-lockfile
yarn dev
```

打开 `http://127.0.0.1:10588`，进入 **设置 → 模型服务 → VGen 本地生成**，
启用并测试模型，再在项目中选择该视频模型。无需连接配置。

程序优先使用 `~/.local/bin/vgen`，否则从 PATH 查找。开发者可通过启动环境中的
`VGEN_CLI` 指定绝对路径、`VGEN_PROFILE` 指定已有配置；普通使用无需设置。
Toonflow 与 CLI 需使用同一系统用户。

## 已实现

- 直接执行 CLI 的预检、提交、状态查询和视频下载命令。
- 文字、首帧、首尾帧生成；参考图片按上传顺序处理。
- 任务记录保存在 Toonflow 的 `data/vgen/jobs.sqlite` 中。
- 同一视频记录重复请求不会重复提交；下载失败可重试。
- 重启后继续查询已有远端任务，并每五秒将完成的视频回填原项目。
- 提交中断且没有得到远端任务编号时标记“结果待核对”，不会自动重提。

## 当前边界

这是源码开发预览，尚未打包成独立安装软件。H3 预置参数仍为 39 帧、24 fps、
1.625 秒，带原生音频；横屏 1344×768、竖屏 768×1344，界面标识为 `768p`。
长视频、其他工作流、参考视频、关闭音频及独立进度/取消界面尚未实现。

关闭弹窗不会取消远端生成，可使用 `vgen task cancel <任务编号>` 取消。
结果待核对时先用 `vgen task list` / `vgen task show` 查明远端状态。
同一数据目录只允许运行一个 Toonflow 实例。

安装脚本可重复执行，会移除旧版 VGen 地址/密钥配置，并更新本地供应商代码。
旧 HTTP 预览的数据目录保留，不自动迁移；当前集成不再使用 HTTP 桥接层。
本地提示词、参考图片和解密后视频尚未自动清理。

验证命令与更多实现细节见 [英文说明](README.md)。
