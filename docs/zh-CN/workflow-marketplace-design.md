# 独立 Workflow Marketplace 设计

> 状态：设计基线，尚未作为生产 Marketplace 交付。文中命令描述目标产品面，不能当作当前版本已经支持的承诺。

## 1. 目标与非目标

Marketplace 的核心目标是让“发布工作流”和“发布 VGen 程序”彻底解耦：发布一个新的 core-only 工作流时，不修改 VGen Git 仓库，不重建 wheel，也不升级 Gateway、Mac CLI 或 Windows Worker。

普通使用者最终只需要一条命令：

```bash
vgen broker workflow-install vgen/example@1.0.0 \
  --worker "Windows GPU Worker" \
  --wait
```

该命令应自动完成可信下载、本地缓存、远程激活、缺失模型安装和就绪检查。普通使用者不应接触：

- `--index`、`--publisher-key`、`--allow-unsigned`；
- 签名私钥、root key、snapshot 或 timestamp；
- license 接受参数；
- HF token，除非缓存缺失且所选模型来源本身受 Hugging Face gate 限制。

Marketplace 第一阶段不解决任意第三方代码的自动执行。普通 workflow ZIP 必须是惰性数据；custom node 使用独立的 Node Pack 供应链。

## 2. 当前实现与真实缺口

当前代码已经具备可复用的底层能力：

- workflow manifest、graph、mapping、checksums 和确定性 package digest；
- ZIP 安全解压、文件数量和解压大小限制；
- Worker 对 capability 包的二次校验、staging 和原子激活；
- 按 SHA-256 存储模型内容，并通过只读硬链接复用到不同 placement；
- 精确到 workflow ref + digest 的静态 readiness。

但当前的 `workflow search/install/update` 只是 legacy/custom registry：显式 `--index` 指向的 JSON 没有标准信任链、过期、冻结和回滚保护。当前 `workflow publish` 也只生成本地 ZIP，并不代表已经上传、进入 catalog 或发布到 stable。`_resolve_workflow` 仍会回退到 wheel 内置资产，因此新增内置工作流仍然依赖发版。

在生产 Marketplace 完成前，必须区分这些状态：

```text
packaged -> uploaded -> cataloged -> installed -> worker_ready -> generation_validated
```

`worker_ready` 当前只表示模型、节点、资源和版本等静态依赖满足，不等于真实生成成功。

## 3. 组件边界

### 3.1 VGen runtime：只读客户端

VGen CLI 只包含 Marketplace 的只读客户端，不持有发布密钥，也不负责修改远端 metadata。建议模块边界：

```text
src/vgen/market/
  models.py          manifest 数据模型
  package.py         checksums、digest、ZIP、内层签名
  local_registry.py  staging、原子安装、immutable ref、lock v2
  catalog.py         CatalogV1 严格 schema 和版本选择
  tuf_client.py      唯一的 TUF、网络和 metadata cache 边界
  resolver.py        workflow ref -> 精确可信 release
```

CLI 只组合这些模块，不继续把网络、签名、安装和发布逻辑堆进 `cli/main.py`。

### 3.2 独立 Marketplace repository

发布侧使用独立仓库和独立流水线，例如 `vgen-market`。它负责 release request、审核、TUF metadata、对象存储发布和公网 fresh-cache 复验。Gateway、Broker 和 Worker 都不拥有 Marketplace 发布权限。

生产 origin、OSS bucket、CDN、KMS、密钥持有人和审批人必须由部署配置明确注入；代码不能擅自假设具体域名或云资源。缺少 bootstrap root 或 origin 时客户端应 fail closed。

### 3.3 普通 Workflow Release

普通工作流 ZIP 只允许惰性数据：

```text
manifest.yaml
workflow.json
mapping.json
README.md
checksums.sha256
artifact.sig
```

模型权重不放进 ZIP。manifest 固定 workflow ref、参数边界、Executor/runtime 兼容范围、资源门槛、模型内容摘要与 placement，以及需要的 node classes。

第一阶段一个 release 只允许一个可执行 variant。GGUF、INT8、novram 等差异先使用不同 workflow ID；在客户端真正实现并验证自动 variant 选择前，不在 catalog 中承诺“多 variant 自动选择”。

## 4. 使用标准 TUF 信任链

Marketplace 不自创 catalog 签名协议。客户端采用 `python-tuf` 的稳定客户端 API：

```text
tuf.ngclient.Updater
tuf.api.metadata
```

依赖建议固定为 `tuf>=7,<8`；不依赖官方标记为非稳定 API 的 `tuf.repository`。发布侧优先采用 `tuf-on-ci` 或等价、经过审计的 TUF 发布流水线，而不是在 VGen CLI 中自行实现 root rotation、threshold counting 和在线签名。

标准 metadata/target 布局示意：

```text
/v1/metadata/
  N.root.json
  timestamp.json
  N.snapshot.json
  N.targets.json
  N.market-catalog.json
  N.publisher-vgen.json

/v1/targets/
  <hash>.catalog-v1.json
  workflows/vgen/<name>/<version>/<hash>.package.zip
```

逻辑 target path 保持稳定：

```text
catalog/v1.json
workflows/vgen/<name>/<version>/package.zip
```

物理 hash 前缀由 TUF consistent snapshot 处理，不另造一套命名或签名规则。

信任关系：

```text
安装器内置、完整且已签名的 root.json
  -> timestamp（新鲜度）
  -> snapshot（metadata 版本集合）
  -> targets / delegations（namespace 权限）
  -> catalog target 与 workflow package target（hash + length）
```

推荐角色：

- root：离线并使用阈值签名；
- top-level targets：只维护 delegation，离线或严格审批；
- `market-catalog`：只授权 `catalog/*`；
- `publisher-vgen`：只授权 `workflows/vgen/*/*/package.zip`；
- snapshot/timestamp：使用独立在线 key/KMS；
- package 内层签名 key：与所有 TUF key 分离，并使用明确的协议域分离。

具体阈值、keyholders、过期周期和轮换日程属于生产运维决策，不能硬编码。单 root key 即使协议允许，也不作为生产安全基线。

Metadata cache 必须有跨进程锁；不能从用户可写 cache 自举 root。每个客户端初始化都从产品提供的 bootstrap root 建立信任，再按 TUF 规则轮换。

## 5. Catalog v1

`catalog-v1.json` 是一个普通、经过 TUF 验证的 target，不是新的签名角色。最小条目示意：

```json
{
  "schema_version": 1,
  "workflows": [
    {
      "ref": "vgen/example@1.0.0",
      "channel": "stable",
      "package_target": "workflows/vgen/example/1.0.0/package.zip",
      "workflow_digest": "sha256:...",
      "installability": "core_only",
      "executor_type": "comfyui",
      "min_vram_bytes": 25769803776,
      "min_ram_bytes": 68719476736
    }
  ]
}
```

Catalog 不包含任意 `package_url`、publisher 公钥、root rotation 或自定义 metadata signature。客户端先让 TUF 下载并验证 catalog，再用 `get_targetinfo()` 和 `download_target()` 获取精确 package target。下载后仍交给 package verifier 交叉检查 ref、workflow digest、manifest 和内层签名。

同一 workflow ID + version 必须不可变。同 ref 不同字节或不同 digest 一律拒绝，修复只能发布新 SemVer。无版本 ref 只选择最高、兼容的 stable 版本，并在任务中固化精确 ref + digest。

## 6. 模型复用、来源和 license

模型字段必须按职责拆分：

```text
内容身份：sha256
一致性检查：size
放置位置：folder + filename
获取与来源说明：sources、revision、gated、license
```

同 SHA-256 且同 size 的内容，不论被多少工作流引用、放到多少目录、使用什么镜像 URL，或后来修正 revision/license 说明，都只下载一个 CAS blob。size 冲突必须拒绝。CAS 已命中时不读取 HF token；只有 cache miss 且实际选择的 source 是 Hugging Face gated source 时才读取 Worker 本机凭据。

License 仅为可选、只读的发布来源信息：

- 不弹接受提示；
- 不保存 license acceptance 状态；
- 不参与安装授权、路由、CAS identity 或 capability identity；
- 未知或缺失 license 不在 Worker 安装协议中阻塞；
- 独立发布政策仍可要求发布者完成人工法律审核，但该政策不下沉为使用者参数。

## 7. 一条命令的安装状态机

`broker workflow-install` 在本地没有精确 release 时自动执行：

1. 使用 TUF 刷新 metadata，并验证 timestamp、snapshot、delegation、target hash/length；
2. 从 catalog 解析精确、兼容且允许安装的 release；
3. 将 package 下载到本地 cache，经过 staging 验证后原子写入 registry；
4. 上传惰性 capability 包，Worker 再次校验并原子激活；
5. Worker 只下载缺失的模型 digest，并从 CAS materialize 到所有 placement；
6. 等待精确 workflow ref + digest 的静态 readiness；
7. 返回 `worker_ready`，而不是声称已经 `generation_validated`。

官方可信的 core-only 工作流不显示 `--approve-nodes`。`--index`、`--publisher-key` 和 `--allow-unsigned` 只保留给明确的 legacy/custom 开发流程，并逐步隐藏或弃用。

本地 `workflow.lock` v2 至少记录 repository id、TUF target path、archive SHA-256、workflow digest 和 trust kind；不能再用单个 `signed: bool` 混淆“包有内层签名”和“来源经过 Marketplace 信任链”。

## 8. 独立发布事务

真正的 publish 不在普通 VGen CLI 中持有生产私钥。推荐流程：

1. 在 VGen 源码之外验证 workflow；
2. 生成确定性 ZIP，使用独立 package key 添加内层签名；
3. 向 Marketplace 仓库提交 release request；
4. CI 校验 namespace、SemVer 不可变、graph/mapping、参数上限、模型 pins 和 installability；
5. 先发布 workflow target，禁止覆盖同路径的不同字节；
6. 更新 catalog target 和 delegated targets；
7. 更新 snapshot；
8. 最后发布 timestamp；
9. 用全新的 metadata cache 从公网执行完整安装复验；
10. 任一步失败时旧 timestamp 继续指向旧 snapshot，未引用 target 仅保留作审计。

发布状态必须分别报告 `uploaded`、`cataloged`、`stable` 和公网复验结果。上传成功不等于已进入 catalog，进入 catalog 也不等于真实生成通过。

## 9. Node Pack 与 Windows Host Protocol

Custom node 是可执行 Python 代码，不能塞回惰性 workflow capability。必须新增独立的 `node_pack_install` 协议和 TUF delegation，至少固定：

- 源码归档/commit 及 SHA-256；
- Python lock 和每个 wheel 的 hash；
- 精确提供的 node classes；
- Python、torch、CUDA、ComfyUI 兼容矩阵；
- Marketplace 审核结果和独立签名；
- staging runtime、`/object_info` 探测、restart、原子激活与 rollback。

安装包不得携带任意安装脚本；复制、依赖安装和探测由 VGen 的固定状态机执行。TUF 只能证明“下载的是审核过的代码”，不能替代隔离和回滚。

当前 Worker 在过渡期只作两项独立的 fail-closed 证明：一是隔离的 `custom_nodes` 根目录中，每个顶层可执行入口都是当前 policy/capability 精确固定的 Git origin + commit，根目录中出现额外 repository、Python 文件、链接/reparse point 或未跟踪内容时一律不 ready；二是工作流所需 class 在 ComfyUI 全局 `/object_info` 中可见。这只能表述为“exact checkout present + class visible”。`/object_info` 不返回 class 的 provider identity，因此这两项事实不能证明该 class 一定由所固定的 repository 提供。真正的 class→provider 绑定必须由 Node Pack 与 Host Protocol v2 提供 pack digest、隔离 staging 和逐 class 的受签名加载回执。

当前 Supervisor、ComfyUI 和 Worker 使用同一个 Windows 用户。Custom node 因而可能读取该用户可读的 Worker credential。Node Pack v1 只能定义为“Owner/Marketplace 审核过的可信代码”，不能宣称是安全沙箱。进一步隔离需要独立 OS identity、ACL、进程边界和凭据代理。

现有远程 `worker_update` 只切换 Worker Python runtime，不能更新 PowerShell host，也不能可靠地单独停启 ComfyUI。首次引入 Host Protocol v2 仍需要一次受管 Windows host bundle 迁移；迁移后新 workflow 和受支持 Node Pack 才能只从 Mac 远程安装。Host 更新、Node Pack 更新和 Workflow 更新必须是三个独立协议，互不冒充成功。

第一阶段 stable 只允许 `custom_nodes: []`。含第三方节点的 release 可标记为 `host_dependency_required` 或 preview；只有 Worker 已上报精确、受管的 node pack digest 时才允许激活，不能伪装成通用一键安装。

## 10. LTX-2.5 发布策略

不同后端使用不同 workflow ID：

```text
vgen/ltx-2.5-distilled-t2v@1.x   官方 INT8，core-only，受 HF gate，32 GB 显存门槛
vgen/ltx-2.5-gguf-q4-t2v@1.x     社区 GGUF Q4，需要 ComfyUI-GGUF Node Pack
vgen/ltx-2.5-novram-t2v@1.x      CPU offload，必须独立实机验证
```

RTX 3090 是 24 GB Ampere，不选择 Blackwell-only 的 NVFP4 variant。GGUF Q4 在同型号 Worker 完成以下验证前只能进入 preview：短片生成、非空 prompt conditioning、VAE decode、音频、取消、重启、第二次 CAS 复用、H3 回归和输出人工检查。模型文件存在、节点探测通过或 progress 到 10% 都不能算真实生成成功。

## 11. 分阶段落地

### 滚动升级合同

本轮代码建立了以下兼容合同，但在正式 release、原生 Windows CI 和实机回归完成前，仍不能视为生产迁移已经完成：

1. 先升级 Gateway。新 Gateway 同时接受 capability install spec v1/v2，并在 Worker view 中提供不可由 Worker 控制的 `gateway_protocol_features.capability_install_spec_version: 2`。CLI 只有在 Gateway 与 Worker 都明确上报版本 2 时才发送带模型和节点标识的 v2 spec；任一端缺少 feature bit（包括新 Worker 先连接已发布的 0.13.10 Gateway）都继续使用原 v1 shape，不能用版本号猜测协议能力。
2. Gateway 不把历史 `workers.capabilities` 自报内容或历史任务分配提升为授权。现有和全新 one-click ComfyUI Worker 在创建/迁移时立即进入严格模式；发布包内精确固定的 H3 ref、package digest、模型 digest 和 node classes 作为旧 machine-admin installer 的最小兼容桥。其他旧自定义工作流必须由 Owner 重新执行 workflow install 建立签名授权；内容寻址 CAS 会复用已存在的相同模型字节，不应重复下载。LTX 等动态能力只从“Owner 签名仍可复验、Worker 已签名回执、状态成功”的 maintenance job 建立授权；heartbeat 不能扩大、切入或退出授权集合。H3 兼容桥应在旧 installer 全部迁移到 Owner attestation 后删除，不能继续扩展成新工作流清单。
3. v1 成功回执只授权精确 workflow ref + digest；其模型依赖由后续逐项签名的 `model_install` 授权。v2 回执额外绑定包内去重后的模型 digest 和 node classes，Gateway 对每次 heartbeat 只公开并调度“授权集合与 Worker 实际上报”的交集。每次 maintenance job 都是独立授权来源。当前 Gateway 已交付精确 workflow identity 的显式 deactivate/uninstall，以及仅撤本次 maintenance source 的自动 rollback API 和审计；共享模型仍有其他有效来源时不会被误撤。Worker 在后续认证 heartbeat 按 Gateway authorization snapshot 原子移除 active index，CAS/package bytes 保留复用。旧 Worker 不执行本地 reconcile，必须升级；但 Gateway 撤权后立即不再把该 release 纳入授权调度集合。
4. 再升级 Worker，并对需要完整依赖标识的 workflow 重跑 capability install。相同 release 的重新激活必须幂等，不能重复下载 CAS 已存在的模型。
5. 新 Worker 向旧 Gateway 上报新失败码时，只允许针对旧 Gateway 明确返回的 `failure_code_unregistered` 做窄兼容回退；签名、任务 id 和 idempotency key 保持不变，其他 4xx 不得静默降级。
6. 任一步失败都保留上一版 Worker runtime、ComfyUI 进程控制和 capability release；自动回滚失败必须进入可诊断的终态，不能以“更新成功”掩盖。

该顺序的目的不是让使用者手工迁移，而是让发布流水线可以先验证 Gateway、再灰度 Worker、最后远程重新授权工作流。正式发布必须提供自动化编排和可观测结果，不能再次要求使用者逐窗敲临时修复命令。

### Phase 0：可靠性基线

- 修复 Worker runtime 指针优先级、维护心跳在线状态和实时 Executor 版本；
- 保存固定、无隐私泄露的 ComfyUI 失败分类和节点标识；
- Registry 使用 UTF-8 路径字节顺序、staging + 原子 rename、同源重定向；
- 让 CLI 在任务失败时显示稳定错误码、task ID 和安全诊断。

### Phase 1：TUF core-only Marketplace + 一条命令安装

- 默认 Marketplace origin 和 bootstrap root；
- TUF client、CatalogV1、local registry lock v2；
- `broker workflow-install` 自动获取官方 stable release；
- 独立 publisher 仓库/CI 和 fresh-cache 公网复验；
- stable 明确拒绝带 custom node 的包。

Phase 1 必须同时交付“一条命令安装”。只交付 `market install`、仍要求使用者手工理解 index/key，不算完成目标体验。

### Phase 2：Host Protocol v2 与 Node Pack

- 一次性迁移受管 Windows host bundle；
- 独立 node pack artifact、安装 job、Comfy generation 和回滚；
- 先支持无原生编译依赖的纯 Python 节点，再逐个验证 GGUF/量化 kernel。

### Phase 3：可选管理服务

只有多人审批、撤回、灰度频道和审计 UI 确实需要时才增加服务端。第一版使用标准静态 TUF repository 即可，不为了“看起来像市场”先引入在线私钥和数据库。

## 12. 最低验收与测试矩阵

- TUF：合法链、错误 threshold、过期/freeze/rollback/mix-and-match、root rotation、delegation 越权、target hash/length 错误、consistent snapshot；
- 网络：非 HTTPS、凭据 URL、跨 origin redirect、非法 target path、超大 metadata/target、TLS/代理失败时不降级验证；
- Catalog：未知字段、重复 ref、非法 SemVer/channel、同 ref 不同 digest、非 core-only stable；
- Registry：跨平台 digest、崩溃恢复、原子 rename、幂等安装、同版本不同字节拒绝、损坏 cache 重下；
- CLI：全新 Mac 一条 broker 命令，无 index/key/sign/license 参数，离线复用已安装精确版本；
- CAS：两个工作流同 digest、不同 placement/source/license 时只有一次网络下载和一个 blob；
- 发布：target 先于 timestamp，每个中断点旧客户端仍能更新，同版本禁止覆盖，公网 fresh-cache 复验；
- E2E：不修改 VGen Git、wheel、Gateway/Worker 版本，向测试市场增加 core-only workflow 并远程安装；
- Node Pack：Phase 1 必须证明带 custom node 的 stable release 被拒绝；
- LTX：只有真实 3090 生成与 H3 回归通过，才能从 preview 提升到 stable。
