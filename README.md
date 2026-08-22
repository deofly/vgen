# VGen

VGen 是一个开源的 GPU 工作流控制面，把公网 Gateway、用户的 Mac CLI/Home Broker 和任意
位置的 Worker 分开部署。任务内容和媒体端到端加密；Gateway 负责身份、准入、调度、租约、
审计与用量，不保存业务明文或解密私钥。

当前项目处于 pre-1.0 Alpha。唯一产品版本来自 `pyproject.toml`，使用完整的
`0.MINOR.PATCH`：bugfix 增加 PATCH，功能或 breaking change 增加 MINOR。

## 当前能力

- 一个 Gateway endpoint 承载多个 Workspace 和 Pool；
- User 与 Broker Device 分离，同一 User 可拥有多台设备；
- 新 Mac 可用一次性邀请执行 `vgen join`，只装 CLI 即可使用 Workspace 共享 Worker；
- Broker 与 Worker 可位于不同网络，User 也可以只拥有 Worker；
- A/B 的 Worker 可加入同一 Pool，任务按 allocation、容量、lease 和 fencing 调度；
- CLI 与 API Service 使用短期、密钥绑定的 session；
- `prepare/commit`、Worker 定向密钥封装、密文 artifact 和 `rekey_required`；
- 内置 ComfyUI Executor，参考工作流 `vgen/minimax-h3-8step` 支持 0 图 t2v、1 图首帧 i2v、
  2 图首尾帧 flf；
- Broker 发起模型下载和纯 Python Worker wheel 更新；
- Mac CLI/Home Broker 通过 `vgen upgrade` 校验 stable release、原子升级并在失败时回滚；
- 同域名 public release channel，以及本机生成密钥的无凭据 Windows Worker 通用包；
- 工作流 market/custom 隔离、不可变 digest、签名和本地执行策略；
- 每 Attempt 可追溯 Worker、consumer channel、GPU/流量指标和 `billing_token`；
- 六位统一错误码、重试动作和 CLI exit code。

v1 仍采用单 Gateway/SQLite，不提供 active-active。Windows Worker 当前以前台 PowerShell
监督器运行，尚未提供 Service、后台常驻或开机自启。SGLang Diffusion 和 Diffusers 只预留
Executor 扩展契约，尚未交付 adapter。API Service 可以完成身份认证和最小 scope 授权，但
当前 v1 暂不为 Service 新发 Workspace Data Key；在补齐与 User 等价的 Owner 签名准入证明前，
Service 不能读取端到端加密的任务内容。

## 两份权威手册

- [用户手册](docs/user-guide.md)：ECS Gateway、管理员/使用者 Mac 加入、Windows Worker、
  ComfyUI、模型下载、Worker 更新、真实 0/1/2 图测试和故障处理。
- [开发与发布手册](docs/developer-guide.md)：架构、安全、API、Executor、工作流市场、开发、
  测试、版本、构建、发行、迁移和扩展规范。

组件目录不再维护另一套 README。Gateway 包内 `INSTALL.txt` 和 Mac ZIP 内 `README.md` 由用户
手册生成；工作流目录中的 README 是被 checksum 固定的包元数据，不是第三份产品手册。

## 协议与贡献

固定的机器可读契约位于 [`schemas/openapi-v1.json`](schemas/openapi-v1.json)。公共 API 只使用
`/api/v1`；旧 shared-token 路由不受支持。开发环境、质量门和发行来源要求见开发手册。

- [贡献指南](CONTRIBUTING.md)
- [安全报告](SECURITY.md)
- [行为准则](CODE_OF_CONDUCT.md)
- [Apache-2.0 License](LICENSE)

不要公开恢复词、私钥、Invite secret、Bootstrap code、Worker 私密 ZIP、session 或签名
artifact URL，也不要把 Gateway 内部端口或 ComfyUI 直接暴露到公网。
