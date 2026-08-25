# 独立 Workflow Marketplace 设计

## 1. 目标

Workflow Marketplace 必须与 VGen 产品版本解耦。新增或更新工作流时，发布者只发布不可变的
工作流包和市场索引，不修改 VGen 源码、不重新构建 wheel，也不升级 Gateway、Mac CLI 或
Windows Worker。

目标操作面：

```bash
# 发布者：在任意工作目录准备、验证并发布
vgen workflow validate ./my-workflow
vgen workflow sign ./my-workflow --key publisher.key
vgen market publish ./my-workflow --channel stable

# 使用者：Mac 获取市场包并让指定 Worker 安装
vgen market install vgen/ltx-2.5-gguf-q4@1.0.0
vgen broker workflow-install vgen/ltx-2.5-gguf-q4@1.0.0 \
  --worker "Windows GPU Worker" --wait
```

`market install` 只把经过市场信任链验证的工作流 release 安装到 Mac 本地 registry；
`broker workflow-install` 沿用现有能力包、模型 CAS、原子激活和 readiness 链路把它交付给
Windows Worker。

## 2. 当前基础与缺口

现有代码已经具备以下基础：

- `WorkflowRegistry` 可验证目录或远程 ZIP 的安全路径、checksums、package digest 和 Ed25519
  发布者签名；
- `workflow search/install/update` 已能读取显式指定的远程 index；
- `broker workflow-install` 已能上传普通工作流 ZIP，让 Worker 在 staging 中重新验证并原子激活；
- Worker 按 SHA-256 共享模型 CAS，同一个 T5、VAE 或 DiT 不会因多个工作流而重复下载；
- 每个工作流独立报告 readiness，一个失败的 release 不会移除已就绪的 H3。

尚缺少的产品层：

- CLI 没有安装器固定的默认 Marketplace origin 和 root trust；
- 远程 index 本身没有签名、过期时间、回滚保护和 publisher delegation；
- `workflow publish` 目前只在本地生成 ZIP，不上传不可变对象，也不原子更新市场索引；
- `_resolve_workflow` 仍把 wheel 内置工作流作为默认兜底；
- 工作流依赖的第三方可执行节点只有说明，没有独立的安全安装通道；
- 市场发布与 VGen 产品发布共用文档和运维概念，容易被误认为必须发新版代码。

## 3. 组件边界

### 3.1 Marketplace Origin

使用独立 HTTPS origin，例如：

```text
https://workflows.vgen.zcbiz.com/
```

它只托管静态、公开、不可变的市场材料，不提供任务 API，不接触 Workspace、prompt、Worker
凭据、HF token 或生成媒体。可以部署到独立 OSS/CDN，也可以先使用当前 ECS 上独立的只读目录和
Nginx virtual host；发布事务必须与 `vgen.zcbiz.com/releases/` stable 频道完全分开。

建议路径：

```text
/v1/root.json
/v1/timestamp.json
/v1/snapshot.json
/v1/catalog.json
/v1/packages/<namespace>/<name>/<version>/<package-sha256>.zip
/v1/node-packs/<publisher>/<name>/<version>/<package-sha256>.zip
```

同一 workflow ID + version 一旦公开，内容和 digest 永不可替换；修复必须增加 SemVer。

### 3.2 市场信任根

CLI 安装器只需固定一次 Marketplace root key。以后 `root.json` 可以通过旧根和新根的阈值签名
轮换，不需要发布 VGen 代码。

信任链：

```text
安装器固定的 Marketplace root key
  -> root.json 中的角色和阈值
    -> timestamp.json（短期有效，阻止冻结攻击）
      -> snapshot.json（固定 catalog 版本和摘要）
        -> catalog.json（授权 publisher key 和所有 release）
          -> publisher 签名的 workflow ZIP
```

第一阶段可采用单 root key + 单 publisher key，但 wire format 从一开始保留阈值、版本、
`expires_at` 和 key rotation 字段，避免以后再次改客户端协议。

### 3.3 Workflow Release

普通工作流 ZIP 继续保持惰性数据：

```text
manifest.yaml
workflow.json
mapping.json
README.md
checksums.sha256
artifact.sig
```

manifest 记录：

- ID、版本、公开参数和 operation；
- Executor/runtime 最低版本；
- 每个硬件 variant 的显存、内存和后端要求；
- 模型的 immutable source revision、size、SHA-256 和目标 placement；
- 只读 license/source 说明；
- 需要的节点类和独立 node-pack ID；
- 发布者 ID 和签名 key ID。

模型权重不放进工作流 ZIP。Worker 从 manifest 固定的来源下载并写入共享 CAS；多个工作流引用
相同摘要时只下载一次。

### 3.4 可执行 Node Pack

第三方 custom node 不能与普通 workflow ZIP 混装。Node Pack 是单独的机器管理员边界，至少包含：

- 固定 Git source 和 commit，或可复现源码归档；
- 文件清单、归档 SHA-256、Python requirements lock 和许可证说明；
- 声明提供的精确 node classes；
- 发布者签名和 Marketplace 审核签名；
- 安装脚本禁止；由 VGen 自己执行受限的复制、依赖安装、临时 ComfyUI `/object_info` 探测；
- staged runtime 验证成功后原子激活，失败时回滚，且不能影响其他工作流。

第一阶段 Marketplace 只自动发布和安装 `custom_nodes: []` 的 core-only 工作流。含第三方节点的
release 可以进入 catalog，但必须标记 `manual_admin_required`，不能伪装成一键安装。

## 4. Catalog v1

`catalog.json` 使用 canonical JSON，并由 snapshot 固定摘要。建议最小结构：

```json
{
  "schema_version": 1,
  "generation": 42,
  "published_at": "2026-08-25T08:00:00Z",
  "publishers": {
    "vgen": {
      "key_id": "sha256:...",
      "public_key": "base64-ed25519-public-key",
      "namespaces": ["vgen/"]
    }
  },
  "workflows": [
    {
      "id": "vgen/example",
      "version": "1.0.0",
      "channel": "stable",
      "package_url": "https://workflows.vgen.zcbiz.com/v1/packages/vgen/example/1.0.0/<sha256>.zip",
      "package_sha256": "...",
      "package_size": 12345,
      "workflow_digest": "sha256:...",
      "publisher": "vgen",
      "publisher_key_id": "sha256:...",
      "variants": [
        {
          "name": "comfyui-core",
          "min_vram_bytes": 25769803776,
          "min_ram_bytes": 68719476736,
          "node_packs": []
        }
      ]
    }
  ]
}
```

客户端只接受同 origin 的 HTTPS package URL，拒绝凭据、跨 origin redirect、版本回退、过期
timestamp、未知 publisher、namespace 越权、重复 ID/version 和同版本不同 digest。

## 5. 独立发布事务

`vgen market publish` 由发布 Mac 执行，但不提交 VGen 仓库：

1. 完整验证 workflow manifest、graph、mapping、模型 pins 和资源门槛；
2. 使用 publisher key 签名并生成确定性 ZIP；
3. 读取远端当前 generation，检查 ID/version 尚不存在；
4. 先上传带 digest 的不可变 ZIP；
5. 生成新的 catalog、snapshot、timestamp 并签名；
6. 以 compare-and-swap 或服务器发布锁原子替换三个元数据文件；
7. 从公网重新下载并验证完整信任链和 ZIP；
8. 失败时保持旧 metadata 生效，新 ZIP 仅作为未引用审计对象保留。

发布凭据只存在于发布 Mac 的 Keychain/受限文件或 ECS RAM Role。普通 Broker、Gateway 和 Worker
不持有 Marketplace 发布权限。

## 6. 客户端与 Worker 流程

推荐把用户操作收敛成一个命令：

```bash
vgen broker workflow-install vgen/example@1.0.0 \
  --worker "Windows GPU Worker" --wait
```

若本地未安装，CLI 自动：

1. 从安装器固定的 Marketplace origin 获取并验证 timestamp/snapshot/catalog；
2. 按 Worker GPU、VRAM、RAM、ComfyUI/Executor 版本选择唯一兼容 variant；
3. 下载并验证 workflow ZIP，写入 Mac 本地 registry；
4. 显示会安装的 core nodes、node packs 和模型总量；
5. 上传 workflow capability ZIP 到 Gateway 临时 artifact；
6. Worker 原子激活工作流；
7. Worker 仅下载缺失的模型 digest，并从 CAS materialize 到目标目录；
8. 精确 workflow ref/digest readiness 变为 `ready` 后返回成功。

Marketplace 不经过 Gateway 分发模型；Gateway 只协调 Owner 授权的 Worker maintenance job。

## 7. LTX-2.5 量化版本的落位方式

同一个模型家族应发布为不同 workflow ID 或 variant，不能覆盖已有 32 GB 官方 INT8 release：

```text
vgen/ltx-2.5-distilled-t2v@1.x       官方 INT8，core-only，32 GB 门槛
vgen/ltx-2.5-gguf-q4-t2v@1.x         社区 GGUF Q4，需要审核后的 ComfyUI-GGUF node pack
vgen/ltx-2.5-novram-t2v@1.x          官方权重 + CPU offload，需独立实机验证
```

RTX 3090 是 Ampere，不应选择标记为 Blackwell-only 的 NVFP4 variant。GGUF Q4 在进入 stable 前必须
在同型号 24 GB Worker 上完成：模型加载、prompt conditioning 非空、短片生成、VAE decode、音频、
取消、Worker 重启、第二次复用 CAS、H3 回归和输出人工检查。只有“模型能加载”不能算 ready。

## 8. 分阶段落地

### Phase 1：独立静态市场，core-only

- 新增默认 Marketplace origin/root trust 配置；
- 实现签名 catalog reader 和 `market install/search/update`；
- 实现独立 publisher 工具与 ECS/OSS 原子部署脚本；
- 把现有 H3、LTX core-only 包从 wheel assets 迁入 Marketplace；
- wheel 内只保留首装兼容桥，不再增加新工作流。

### Phase 2：一条命令安装

- `_resolve_workflow` 在本地缺失时安全查询默认 Marketplace；
- 根据 Worker capability 自动选 variant；
- `broker workflow-install` 合并 market install、capability activate、model install 和 readiness；
- CLI 默认只显示工作流、下载量、预计资源和最终状态。

### Phase 3：签名 Node Pack

- 独立 node-pack schema、审核签名、staging ComfyUI 和原子 runtime generation；
- 先支持无原生编译依赖的纯 Python 节点；
- GGUF、特殊量化 kernel 等单独做硬件/torch/CUDA 兼容矩阵；
- 任何 node-pack 失败不改变既有 H3 和其他 ready workflow。

### Phase 4：Marketplace 管理服务（可选）

只有需要多人审核、撤回、灰度频道和发布审计 UI 时才增加服务端 API。静态签名市场已经满足
独立发布和全球只读分发，不应为了第一版先引入数据库、账号和在线签名私钥。

## 9. 验收标准

- 从 VGen 源码之外的目录发布新 workflow，Git `main`、产品版本和 Gateway runtime 均不变化；
- 公网不可变 ZIP 与签名 catalog 可独立验证；
- 新 Mac 可通过固定 root trust 安装，不能信任 index 自带的未知 publisher key；
- 同版本不同字节、回滚 index、过期 metadata、跨 origin URL 全部拒绝；
- 同一模型 digest 在两个工作流之间只下载和存储一次；
- 新工作流失败或被撤回不会使已就绪 H3 失效；
- custom node 不会通过普通 workflow ZIP 静默执行；
- 发布、安装、Worker 激活和真实生成是四个独立可观察状态。
