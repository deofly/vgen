[English](README.md) | 简体中文

# VGen

VGen 是一个 GPU 工作流平台，由 Gateway、Broker 和远程 Worker 共同运行工作流。它帮助团队
共享 GPU 资源、执行视频生成任务，并让任务内容和媒体始终保持端到端加密。

## 功能

- 在多个用户、Workspace 和 Pool 之间共享 GPU 资源。
- 通过 Broker 控制远程 GPU Worker 执行工作流。
- 使用 ComfyUI 执行文生视频、首帧图生视频和首尾帧视频任务。
- 在客户端和 Worker 之间安全传输任务媒体。
- 发布并激活经过审核的工作流、复用共享模型内容，并远程安装模型或更新 Worker。
- 按资源容量可靠地调度和执行任务。

## 环境依赖

本地预览 Gateway 需要：

- Git
- Docker 与 Docker Compose

完整 GPU 环境需要 Python 3.11+、支持的 GPU 运行时（例如 ComfyUI）以及工作流所需模型。
部署和 Worker 配置请参考[用户手册](docs/zh-CN/user-guide.md)。

## 快速上手

无需 ECS 和 GPU 即可在本地预览 Gateway：

```bash
git clone https://github.com/deofly/vgen.git
cd vgen
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example up --build -d
curl --fail http://127.0.0.1:8000/healthz
```

响应应包含 `"ok":true`。体验结束后运行：

```bash
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example down
```

该 Compose 配置只适合本地预览，不能作为生产部署模板。

生成真实视频前，请先按[用户手册](docs/zh-CN/user-guide.md)完成 Gateway、Broker、Worker、
ComfyUI 和模型配置，然后运行：

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

## API

机器可读的 API 契约位于 [`schemas/openapi-v1.json`](schemas/openapi-v1.json)。公共 API 使用
`/api/v1`。

独立的 [Python 和 Java SDK](sdks/README.zh-CN.md)提供 API Service 凭据、请求签名和端到端加密
能力，不需要导入 CLI 内部模块。

## 其他重要文档

- [用户手册](docs/zh-CN/user-guide.md)：Gateway 部署、Broker 接入、Worker、模型安装、
  更新、真实任务和故障处理。
- [开发与发布手册](docs/zh-CN/developer-guide.md)：架构、安全、协议、开发、测试、构建、
  发布、迁移和扩展规范。
- [SDK 兼容性协议](docs/zh-CN/sdk-compatibility.md)：凭据、签名、加密和跨语言兼容规则。
- [安全策略](SECURITY.md)：支持范围和私密漏洞报告方式。
- [Apache-2.0 License](LICENSE)

不要公开恢复词、私钥、Invite secret、Bootstrap code、Worker credential、session 或签名
artifact URL。
