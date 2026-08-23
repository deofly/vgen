[English](README.md) | 简体中文

# VGen

VGen 是一个开源 GPU 工作流控制面，由公网 Gateway、Mac CLI/Home Broker 和远程 Worker
组成。任务内容和媒体端到端加密；Gateway 负责身份、准入、调度、租约、审计和用量，不保存
业务明文或解密私钥。

## 功能

- 在多个 User、Workspace 和 Pool 之间共享 GPU Worker。
- Worker 与 Broker 可运行在不同机器和网络中。
- 按 allocation、容量、lease 和 fencing 安全调度任务。
- 通过内置 ComfyUI Executor 执行文生视频、首帧图生视频和首尾帧视频任务。
- CLI、Worker 与私有 OSS 使用短期凭据直接传输加密任务媒体。
- 由 Mac Broker 安装固定版本的工作流模型并更新 Windows Worker。
- Mac CLI/Home Broker 支持校验、原子升级和失败回滚。
- Gateway API 与公开安装包使用独立域名。
- 为每个 Attempt 记录 Worker、GPU、网络和 `billing_token` 用量。

## 环境依赖

本地预览 Gateway 需要：

- Git
- Docker 与 Docker Compose

完整 GPU 环境需要：

- ECS：Python 3.11+、Nginx、systemd、HTTPS、私有 OSS 和 STS；
- Mac：Python 3.11+，用于 CLI/Home Broker；
- Windows GPU 电脑：PowerShell 5.1+、ComfyUI 0.30.0+ 和工作流所需模型。

Windows Worker 当前在前台 PowerShell 窗口中运行。Gateway 内部端口和 ComfyUI 必须保持
私有，只对外开放 Gateway HTTPS 地址。

## 快速上手

无需 ECS 和 GPU 即可在本地预览 Gateway：

```bash
git clone https://github.com/deofly/vgen.git
cd vgen
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example up --build -d
curl --fail http://127.0.0.1:8000/api/v1/health
```

响应应包含 `"ok":true`。体验结束后运行：

```bash
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example down
```

该 Compose 配置只适合本地预览，不能作为生产部署模板。

生成真实视频前，请先按[用户手册](docs/zh-CN/user-guide.md)完成 Gateway、Mac、Windows
Worker、ComfyUI 和模型配置，然后运行：

```bash
vgen gateway health
vgen task preflight
vgen task submit "电影感的海上日出" \
  --wait --output-dir ~/Downloads/VGen-output
```

打开 CLI 输出的本地绝对路径，确认视频可以播放并检查画面质量。

## 本地开发

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[gateway,broker,worker-comfyui,oss,dev]'
python -m ruff check .
python -m pytest
python tools/export_openapi_v1.py --check
python tools/check_public_repository.py
```

## 贡献

提交改动前请阅读[贡献指南](CONTRIBUTING.md)。保持提交范围清晰，为行为变化补充测试，禁止
提交 credential、恢复材料、本地数据库、生成的发行物或机器专用配置。社区协作约定见
[行为准则](CODE_OF_CONDUCT.md)。

## 协议

机器可读的 API 契约位于 [`schemas/openapi-v1.json`](schemas/openapi-v1.json)。公共接口使用
`/api/v1`，不支持旧 shared-token 路由。已经发布的六位业务错误码是永久兼容标识。

## 其他重要文档

- [用户手册](docs/zh-CN/user-guide.md)：Gateway 部署、Mac 接入、Windows Worker、模型安装、
  更新、真实任务和故障处理。
- [开发与发布手册](docs/zh-CN/developer-guide.md)：架构、安全、协议、开发、测试、构建、
  发布、迁移和扩展规范。
- [安全策略](SECURITY.md)：支持范围和私密漏洞报告方式。
- [Apache-2.0 License](LICENSE)

不要公开恢复词、私钥、Invite secret、Bootstrap code、Worker credential、session 或签名
artifact URL。
