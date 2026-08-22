# VGen 用户手册

本文是 VGen 面向部署者和使用者的唯一操作手册。它覆盖 ECS Gateway、Mac CLI/Home
Broker、Windows GPU Worker、模型下载、Worker 更新以及真实视频任务。开发环境、构建和发行
不在本文展开。

文中的占位符含义如下：

- `<版本>`：下载包的版本，例如 `0.3.0`；
- `<域名>`：Gateway 的小写 DNS 域名，例如 `vgen.example.com`，**不带** `https://`；
- `<job_id>`、`<worker_id>`、`<enrollment_id>`：CLI 输出的真实 ID，不要连尖括号一起输入。

## 1. 三端架构和安装顺序

```text
ECS Gateway（公网 HTTPS 控制面和密文任务状态）
        ↑
        ├── 管理员 Mac CLI / Home Broker（管理 Workspace 和 Worker）
        ├── 其他 Mac CLI（加入 Workspace、提交任务，不需要 Broker）
        └── Windows Worker + ComfyUI（GPU 推理、模型和输出）
```

按以下顺序安装：

1. 在 ECS 全新安装或升级 Gateway，并确认公网健康；
2. 在 Mac 安装 CLI/Home Broker，完成首次身份和 Workspace 初始化；
3. 其他 Mac 从同一 Gateway 域名安装 CLI，用一次性邀请加入 Workspace；
4. 在 Windows 安装 ComfyUI Desktop 或解压 ComfyUI Portable；
5. Windows 下载无凭据通用 Worker ZIP，用一次性邀请登记并启动 Worker；
6. Worker 缺模型时，由管理员 Mac 上的 Broker 发起模型下载；
7. 分别提交 0、1、2 张图片的视频任务进行验收。

当前 Gateway 由 systemd 常驻，Mac Home Broker 由安装器配置为当前用户的 LaunchAgent。
Windows Worker 暂时必须保持 PowerShell 窗口打开；当前版本不安装 Windows Service，也不
提供后台常驻或开机自启。

> **工作流安装不等于模型权重下载。** Mac 初始化时安装的是
> `vgen/minimax-h3-8step` 工作流清单、参数定义和 ComfyUI 图。实际模型权重位于 Windows
> 模型目录中；缺少权重时必须完成第 6 节的 Broker 模型安装任务。

## 2. 安装包、前置条件和校验

公开发行物包括：

| 文件 | 用途 |
|---|---|
| `vgen-gateway-<版本>.tar.gz` | ECS Gateway 全新安装或升级 |
| `VGen-macOS-<版本>.zip` | Mac CLI/Home Broker 首装或升级 |
| `vgen-windows-worker-installer-<版本>.zip` | 可公开下载、无凭据的 Windows Worker 首装包 |
| `vgen-<版本>-py3-none-any.whl` | 经管理员复核后远程更新 VGen Worker |

`vgen worker bundle` 生成的 `vgen-worker-<名称>.zip` 是某一台 Worker 的私密包，内含
Worker 私钥，不能公开分发，也不要发送到群聊、公开网盘或代码仓库。

开始前：

- 从可信 Release 页面下载，并核对页面公布的包级 SHA-256；
- ECS 已配置指向本机的域名和有效 HTTPS 证书，并安装 Python 3.11+、Nginx 和 systemd；
- Mac 已安装 Python 3.11+，且能访问 PyPI；
- Windows 已安装 ComfyUI Desktop 或准备好官方 Portable；MiniMax H3 要求实际
  ComfyUI 运行版本不低于 `0.30.0`；
- 不要把 Gateway 内部端口 `8010` 或 ComfyUI `8188` 暴露到公网。

Gateway 包解压后还要校验包内文件：

```bash
sha256sum -c SHA256SUMS
```

公开安装包由同域名 `/releases/<版本>/` 提供；`/api/v1/releases/channels/stable` 返回当前
版本、大小和 SHA-256。Mac 还提供固定的 `/releases/install-macos.sh` 引导入口。先下载并
阅读它，再单独运行，**不要使用 `curl | sh`**。该脚本读取同源 stable API，校验不可变版本
清单的摘要、Mac ZIP 的大小和 SHA-256，并拒绝跨域或非 HTTPS 下载。

Mac 安装器还会校验 ZIP 内的 `SHA256SUMS` 和 wheel 元数据。这些 HTTPS + SHA-256 检查能
发现传输、缓存或存储篡改，但不是发行者数字签名。目前 ZIP 尚未提供 Apple notarization，
Windows ZIP 也尚未提供 Authenticode；正式对外发行前仍需补齐。

<!-- VGEN_GATEWAY_INSTALL_BEGIN -->

## 3. ECS Gateway

以下命令中的每个 `setup-gateway.sh` 动作都明确携带 `--domain <域名>`。如果当前 SSH
用户是 `root`，可以省略 `sudo`。

### 3.1 全新安装

先停止旧 Worker 领取任务并等待活动任务结束，再上传 Gateway 包：

```bash
install -d -m 0700 /root/vgen-gateway-install
tar -xzf /root/vgen-gateway-<版本>.tar.gz \
  -C /root/vgen-gateway-install --strip-components=1
cd /root/vgen-gateway-install
sha256sum -c SHA256SUMS
sudo ./setup-gateway.sh install --domain <域名>
```

按提示再次输入相同域名，并确认旧任务已结束。安装器会先验证
`127.0.0.1:8010`，再切换 Nginx；失败时恢复原路由。安装器不会修改 OSS、RAM Role、
安全组或其他云权限。

### 3.2 原地升级

已有 Gateway 时不要清空数据库，也不要重新 bootstrap。把新包解压到新的私有目录：

```bash
install -d -m 0700 /root/vgen-gateway-upgrade
tar -xzf /root/vgen-gateway-<版本>.tar.gz \
  -C /root/vgen-gateway-upgrade --strip-components=1
cd /root/vgen-gateway-upgrade
sha256sum -c SHA256SUMS
sudo ./setup-gateway.sh upgrade --domain <域名>
```

升级会备份数据库、runtime 和配置，健康检查失败时自动恢复旧版本。重复升级到已经健康运行
的同一版本是安全的幂等操作。

从 0.2.2 升级到 0.3.0 后，先在 Workspace Owner 的 Mac 升级 CLI，再运行一次：

```bash
vgen workspace owner-migrate
```

已有可验证 Owner genesis/pin 时命令只报告当前状态；真正的旧 Workspace 会显示一次
legacy TOFU 警告，要求核对 Gateway、Workspace、User 和 root key ID 并输入确认词。完成前，
邀请 User、发放或轮换 Workspace key 都会默认拒绝，不会静默信任 Gateway 的 Owner 字段。

早期内部测试 Gateway 使用过 `2.0.0a1` 标识，之后项目正式改用 `0.MINOR.PATCH`。从该
历史版本升级必须使用 `0.2.2` 或更高版本的安装包；安装器只把**完全匹配的** `2.0.0a1`
视为迁移前版本。其他预发布字符串、未知版本和真正的高版本降级仍会被拒绝。不要手工修改
已安装 wheel 的 metadata、Gateway 数据库或包内 `SHA256SUMS`。

### 3.3 中断恢复、状态和路由回滚

只有安装停在“已创建 runtime 和环境文件，尚未初始化数据库/systemd/Nginx”的受支持状态
时才运行：

```bash
sudo ./setup-gateway.sh resume --domain <域名>
```

Gateway 本机已经健康，但先前 Nginx 切换因为短暂 502 回滚时运行：

```bash
sudo ./setup-gateway.sh activate --domain <域名>
```

查看服务、安装状态和公网健康：

```bash
sudo ./setup-gateway.sh status --domain <域名>
curl --fail --silent https://<域名>/api/v1/health
```

响应应包含 `"ok":true`。要把公网 Nginx 路由恢复到安装前保存的旧服务，运行：

```bash
sudo ./setup-gateway.sh rollback --domain <域名>
```

`rollback` 只恢复保存的旧 Nginx 路由，不删除 v1 数据，也不是任意数据库版本降级工具。
上述变更命令会再次要求输入域名；`activate`、`upgrade`、`rollback` 还会要求二次确认。

### 3.4 首次 Bootstrap code

只有全新安装后的第一个 Mac 需要 Bootstrap code。先在 Mac 上打开安装器，等隐藏输入框出现，
再在 ECS 显示：

```bash
sudo cat /var/lib/vgen-v1/bootstrap-code
```

只把它粘贴进 VGen 的隐藏提示，不要放到命令、聊天、截图或 shell history。Mac 初始化成功
后删除服务器上已失效的副本：

```bash
sudo rm -f /var/lib/vgen-v1/bootstrap-code
```

<!-- VGEN_GATEWAY_INSTALL_END -->

## 4. Mac CLI 和 Home Broker

### 4.1 首次安装

1. 核对 `VGen-macOS-<版本>.zip` 的发行页 SHA-256，然后解压；
2. 双击 `install.command`；如果 Gatekeeper 首次阻止，右键文件并选择“打开”；
3. 按提示填写显示名称，离线、按顺序抄写 24 个恢复词并完成确认；
4. 隐藏输入框出现后，按第 3.4 节读取并粘贴一次性 Bootstrap code；
5. 等待安装器明确显示初始化完成且 Home Broker 已真实上线。

安装器会创建用户身份、默认 Workspace、默认 GPU Pool、Logical Home Broker 和 Broker
Device，并安装官方工作流清单。用户不需要复制这些资源的内部 ID。

恢复词永远不要上传 Gateway，也不要发送给任何人。Bootstrap code 不能代替恢复词。

### 4.2 升级或重装 Mac CLI

首次安装包含自升级能力的版本后，后续只需运行：

```bash
vgen upgrade
```

CLI 会查询当前 Profile 所绑定 Gateway 的 stable 版本，下载并校验不可变 manifest、安装包大小、
SHA-256、ZIP 路径和包内 `SHA256SUMS`，然后安装到新的不可变版本目录。新 CLI 校验成功后才切换
`~/.local/bin/vgen` 并刷新 Home Broker；刷新失败时自动恢复旧 CLI 和旧 Broker。身份、Gateway、
Workspace、Broker 配置以及旧版本目录都会保留，不需要恢复词、Bootstrap code 或再次执行
`setup`。

只检查是否有更新：

```bash
vgen upgrade --check
```

自动化环境可显式使用 `vgen upgrade --yes`；日常交互升级默认要求确认。当前 CLI 不是官方受管
安装、安装标记损坏或升级回滚失败时，重新运行 Gateway 首页提供的一键安装命令恢复，不要手工
修改版本目录或符号链接。直接下载并双击新版 `install.command` 仍作为恢复路径保留。

完成后可以检查：

```bash
vgen profile show
vgen gateway health
vgen broker status
vgen broker local-status
```

`broker status` 显示 Gateway 最近收到的每台 Broker Device 运行版本、协议版本、最后心跳和是否有
可用升级；`broker local-status` 直接检查这台 Mac 的 LaunchAgent、进程 PID、实际运行版本和 CLI
版本。升级器和安装器都会执行 `broker service-refresh`，把已存在的 Home Broker 切换到新 CLI
环境，不需要重新运行 `setup`、重新绑定设备或再次输入 Bootstrap code。

### 4.3 其他 Mac 加入并使用共享 Worker

如果对方是第一次使用 VGen、这台 Mac 上没有已绑定 User 的 Profile，Workspace Owner 先在
自己的 Mac 运行：

```bash
vgen workspace invite --kind user --method direct_invite \
  --relationship member --wait
```

如果对方已经在这台 Mac 上登录了同一 Gateway 的 VGen User，只是要加入另一个 Workspace，
则必须发成员邀请，不能再发创建新 User 的邀请：

```bash
vgen workspace invite --kind workspace_member --method direct_invite \
  --relationship member --wait
```

对方不确定时先运行 `vgen profile show`：能看到同一 Gateway 和 `user_id` 就使用
`workspace_member`；尚无可用 Profile 才使用 `user`。两种 Invite 不能互换，CLI 也不会自动
把一种转换成另一种。

CLI 会先输出完整的一次性邀请，然后等待对方领取。只通过可信的一对一渠道发送完整 URI；
不要发群聊、工单或截图，也不要把它放入命令参数。0.3.0 中只有 Workspace Owner 可以签发
User/成员邀请并发放 Workspace 加密密钥；普通 Admin 可以管理 Pool 等非加密资源，但不能代替
Owner 完成下面的密钥核验。

新 Mac 只安装 CLI，不安装 Home Broker、Worker、ComfyUI 或 Docker：

```bash
curl --fail --location --output install-macos.sh \
  https://<域名>/releases/install-macos.sh
less install-macos.sh
sh install-macos.sh
"$HOME/.local/bin/vgen" join --gateway https://<域名>
```

全新 User 的 `join` 会在本机生成用户和设备密钥，显示需要离线保存的 24 个恢复词；已有 User
则沿用当前 Profile 的设备身份。随后都会出现隐藏邀请输入框。粘贴 Owner 发送的完整 URI；输入
不会显示，也不会写入 shell history。领取后，加入方会显示五组 User 核验码。这个码不是登录
密码，但必须原样通过可信的一对一渠道告诉 Owner；它由加入方本机的完整 User/Device 公钥声明
计算，不能从 Gateway 后台复制一个值来代替。

仍在 `--wait` 的 Owner CLI 会提示输入这五组核验码。双方核对一致后，Owner CLI 才签署该 User
的 Workspace 加密准入并发放密钥。若 Owner 的等待命令已经退出，可显式运行：

```bash
vgen workspace key-grant-enrollment <enrollment_id> \
  --verification-code <加入方显示的五组核验码>
```

若使用 `invite_approval`，则批准和密钥准入合并为：

```bash
vgen workspace decide <enrollment_id> --approve \
  --verification-code <加入方显示的五组核验码>
```

加入方安装工作流、取得 Workspace 密钥并选择 Pool 后，CLI 才会切换默认 Workspace。

如果 Owner 尚未批准或密钥发放暂未完成，新 Mac 会明确显示 pending，不需要再次使用已经消费
的一次性邀请。Owner 完成核验和发放后，加入方只运行：

```bash
vgen join --resume
```

完成后该 Mac 可以直接 `vgen task submit`，任务会由 Workspace/Pool 中可用的共享 Worker 执行；
它不能管理其他用户拥有的 Worker。

## 5. Windows Worker 和 ComfyUI

### 5.1 推荐：无凭据通用包和一次性 Worker 邀请

管理员创建只可使用一次、领取后还需管理员批准的 Worker 邀请：

```bash
vgen worker invite --name "Windows GPU Worker" --pool "默认 GPU 池"
```

保存输出中的 `enrollment_id`，只把完整邀请 URI 发给目标 Windows。Windows 可用浏览器下载，
也可在 PowerShell 下载当前明确版本：

```powershell
Invoke-WebRequest -UseBasicParsing `
  "https://<域名>/releases/<版本>/vgen-windows-worker-installer-<版本>.zip" `
  -OutFile ".\vgen-windows-worker-installer-<版本>.zip"
Expand-Archive ".\vgen-windows-worker-installer-<版本>.zip" ".\VGen-Worker"
Set-Location ".\VGen-Worker"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ".\enroll-worker.ps1"
```

脚本在 Windows 本机生成 Worker 私钥，并在隐藏输入框读取一次性邀请；公开 ZIP、Gateway 和
管理员 Mac 都不生成或保存这把私钥。领取成功后 Windows 会显示完整的 claim 绑定验证码；
通过可信的一对一渠道把这个验证码发给管理员。管理员只在看到 Windows 本机显示的完整值后
运行：

```bash
vgen worker approve-enrollment <enrollment_id> --code <Windows显示的完整验证码>
```

CLI 会用验证码重新绑定待审批 claim；不匹配时拒绝签发 Worker certificate 和 Pool allocation，
防止 Gateway 或中间人替换 Worker 公钥。批准后 Windows 会自动继续现有的 ComfyUI 检测和
Worker 安装。这个通用 ZIP 可以公开缓存，但 Invite 仍是一次性秘密，不能打进安装包或放在
PowerShell 参数中。

### 5.2 兼容方式：在 Mac 生成指定 Worker 私密包

默认 Workspace 只有一个 Pool 时运行：

```bash
vgen worker bundle
```

存在多个 Pool 时按名称选择：

```bash
vgen worker bundle --pool "我的 3090"
```

CLI 会登记 Worker、完成 Pool 和费率批准，并在 `~/Downloads` 生成私密 ZIP。只通过可信的
点对点方式把它交给目标 Windows 机器。

从 `0.1.x` 首次迁移到支持 Broker 维护任务的 `0.2.x` 时，旧 credential 缺少 Owner 根公钥
信任锚，必须撤销旧 Worker 并重新生成一次 bundle：

```bash
vgen worker list
vgen worker revoke <worker_id>
vgen worker bundle
```

这是一项一次性迁移；完成后日常 VGen Worker wheel 更新由 Broker 发起。

### 5.3 私密包首次启动

1. 安装 ComfyUI Desktop，或解压官方 ComfyUI Portable；Desktop 多实例管理器需要先创建并
   启动一次本地 Standalone；
2. 完全退出所有正在运行的 ComfyUI；
3. 把私密 Worker ZIP 解压到本地目录；
4. 双击 `start-worker.cmd`。

也可以在解压目录运行：

```powershell
.\setup-worker.ps1
```

安装器会自动检查 Gateway，准备隔离的 VGen runtime 和 custom nodes，必要时只在
`127.0.0.1:8188` 启动 ComfyUI，然后以前台方式运行 Worker。缺模型不会使安装失败：Worker
会以 `maintenance-only` 在线，等待 Broker 发起模型下载。

为同一台电脑创建新 Worker 时，安装器会先检查 `%LOCALAPPDATA%\VGen\comfyui\wrk_*` 中旧
VGen Worker 已安装的固定版本 custom nodes。只有仓库来源、固定 revision、工作区完整性和
目录安全检查全部通过才会复制到新 Worker 的隔离目录；本机没有合格副本时才访问 GitHub。
因此即使准备重新接入 Worker，也不要删除整个 `%LOCALAPPDATA%\VGen`。

日志在 `Reusing locally reviewed custom node` 后仍会显示 `Cloning into`，有时还会显示
`remote: Enumerating objects`；这是 Git 从本机已校验仓库创建独立副本时的正常输出，不代表
再次从 GitHub 下载。安装器会为 Windows Git 显式启用长路径，并使用较短的随机暂存目录。
若旧安装器曾留下名称严格符合
`.节点目录.vgen-staging-<32 位十六进制字符>` 的暂存目录，普通启动会先做归属和重解析点
检查，再仅清理这些 VGen 旧暂存目录；`-CheckOnly` 始终只读。

安装器会自行收紧私密 credential 的 Windows ACL，不需要用户先运行 `icacls` 或手工修改
JSON。

Python、pip、winget 在安装时显示的进度只写入当前窗口，不会被当作 Python 或 Git 路径。
如果某次安装中断，保留 `%LOCALAPPDATA%\VGen` 和模型，直接用修复后的 Worker ZIP 重新运行
`start-worker.cmd`；安装器会继续准备隔离环境，不需要手工删除 `worker-runtime-*`。

看到 Worker 开始轮询后保持唯一的 PowerShell 窗口打开。VGen 启动的 ComfyUI 会复用这个
控制台，不应再弹出第二个空白 Terminal；其输出仍写入 `%LOCALAPPDATA%\VGen\logs`。按
`Ctrl+C` 可让脚本停止本次由它启动的 Worker 和 ComfyUI；如果直接强制关闭窗口导致残留
进程，先在任务管理器结束残留的 ComfyUI/Python，再重新启动。

### 5.4 Desktop、Portable 和自定义数据目录

脚本会检查 AppData、Program Files、Program Files (x86)、ComfyUI Desktop 安装记录和常见
Portable 目录，并自动判断安装类型：

- 只找到一套时自动使用；
- 找到多套时在当前窗口列出编号供选择；
- 默认目录都找不到时，先让用户选择 `ComfyUI Desktop` 或 `ComfyUI / Portable`，再粘贴
  应用目录、`ComfyUI.exe`、`main.py` 或真正的 ComfyUI 目录；
- Desktop 使用自定义数据存储目录但安装记录无法确认时，会提示用户粘贴数据目录，不会猜测
  固定的 Documents 路径，也不会扫描整个磁盘。

高级排障或无人值守运行可以明确指定：

```powershell
.\setup-worker.ps1 `
  -ComfyUIRoot "D:\ComfyUI_windows_portable\ComfyUI" `
  -ComfyUIDataRoot "D:\ComfyUI-data"
```

`-ComfyUIRoot` 是代码/应用位置，`-ComfyUIDataRoot` 是 Desktop 的数据和 Python 环境位置，
两者可以不同。VGen 自身数据仍隔离在 `%LOCALAPPDATA%\VGen`，不会写入 Program Files，也
不会覆盖用户原有 custom nodes。只读预检可运行：

```powershell
.\setup-worker.ps1 -CheckOnly
```

### 5.5 重装同一台 Worker

日常修复不需要创建新的 Worker：

1. 关闭前台 Worker；
2. 只删除上次 ZIP 的**解压目录**；
3. 从原来的私密 ZIP 重新解压并双击 `start-worker.cmd`。

不要删除 ComfyUI、模型、`%LOCALAPPDATA%\VGen` 或私密 ZIP 中的 credential。复用同一个 ZIP
会保留同一 Worker 身份，不会在 Gateway 产生重复记录。

## 6. Broker 发起模型下载和 Worker 更新

这些命令都在 Mac 上运行，并要求 Windows Worker 的前台 PowerShell 仍在线。正常由
`vgen worker invite` 或 `vgen worker bundle` 创建的 Worker 已绑定当前 Home Broker；如果
CLI 明确报告没有 manager Broker，先运行：

```bash
vgen worker manager-set "Windows GPU Worker"
```

### 6.1 安装缺失模型

```bash
vgen broker model-install vgen/minimax-h3-8step \
  --worker "Windows GPU Worker" --wait
```

CLI 会显示缺失模型总量和所需许可证。交互运行时，按提示阅读许可证并输入显示的完整许可证
标识以确认接受。下载支持断点续传，只有路径、固定来源/revision、大小和 SHA-256 全部通过
后才原子安装；已有冲突文件不会被覆盖。

查看和取消维护任务：

```bash
vgen broker maintenance-list --worker "Windows GPU Worker"
vgen broker maintenance-show <job_id>
vgen broker maintenance-cancel <job_id>
```

取消会阻止未开始的任务；正在下载的 Worker 会在下一次取消检查时停止。已校验并成功安装的
文件不会因为随后取消而删除。

### 6.2 更新 VGen Worker

先从可信 Release 获取并复核新的纯 Python VGen wheel，再运行：

```bash
vgen broker worker-update ~/Downloads/vgen-<版本>-py3-none-any.whl \
  --worker "Windows GPU Worker" --wait
```

更新等待 Worker 空闲后安装到独立 runtime。Windows 前台监督器负责切换版本、重新上线和
激活失败时回退上一 runtime。

该命令只更新 VGen Worker wheel，**不会**更新 Gateway、Mac CLI、ComfyUI、custom nodes、
Python、CUDA、显卡驱动或模型。授权维护 Broker 能向 Worker 部署代码，因此只使用管理员
已经核验来源和摘要的 wheel。

## 7. 真实 0/1/2 图测试

先确认 Gateway、Broker 和 Worker 状态：

```bash
vgen profile show
vgen gateway health
vgen broker status
vgen worker list
vgen broker maintenance-list --worker "Windows GPU Worker"
```

模型任务必须成功，Worker 不能仍处于 `maintenance-only`。输出目录不存在时 CLI 会按需创建。
提交前先做一次只读能力预检：

```bash
vgen task preflight
```

它使用与真实提交相同的公开 workflow requirements，但不创建 Task/Attempt、不预留 Worker、
不上传 prompt/图片，也不产生用量或计费。输出会区分 `ready`、没有已分配 Worker、Worker
offline/busy/maintenance、capability mismatch（执行器/模型/版本/内存/显存）和 rate 未审批。
1 图或 2 图模式可相应增加 `--image`、`--last-image`，这些文件在预检中不会上传。

### 0 张图：文生视频

```bash
vgen task submit "电影感航拍，清晨云海翻涌，镜头缓慢向前" \
  --wait --output-dir ~/Downloads/VGen-output
```

### 1 张图：图片作为首帧

```bash
vgen task submit "人物自然眨眼并轻轻转头，镜头稳定" \
  --image ~/Downloads/first.png \
  --wait --output-dir ~/Downloads/VGen-output
```

### 2 张图：首尾帧

```bash
vgen task submit "镜头平滑推进，主体动作连续自然" \
  --image ~/Downloads/first.png \
  --last-image ~/Downloads/last.png \
  --wait --output-dir ~/Downloads/VGen-output
```

`--last-image` 不能脱离 `--image` 单独使用。验收时不仅要看到 `succeeded`，还要打开 CLI
输出的本地绝对路径，确认视频可播放并符合 0/1/2 图语义和预期质量。

## 8. Worker 退出与设备移除

### 8.1 Worker 正常退出或立即撤销

先从 `vgen worker list` 取得 Worker ID。正常退出会进入 draining，停止领取新任务并等待当前
Attempt 完成：

```bash
vgen worker leave <worker_id>
```

需要立即停止时使用：

```bash
vgen worker leave <worker_id> --force
```

Worker 丢失或疑似被入侵时直接撤销：

```bash
vgen worker revoke <worker_id>
```

`--force` 和 `revoke` 会使当前 lease/fencing token 失效，迟到结果不能覆盖新 Attempt。撤销后的
Worker ID 不能“复活”；重新接入需要运行 `vgen worker bundle` 创建新的 Worker。日常重装同一
Worker 时不要先撤销，按第 5.5 节复用原私密 ZIP 即可。

### 8.2 Mac Device 移除和换机边界

移除当前 Mac 前，必须确认恢复词可用或已有另一台已授权设备。查看当前 Device ID：

```bash
vgen identity show
```

确认后撤销当前 Device 并清理本地 identity/session：

```bash
vgen identity revoke --forget-local
```

丢失设备应由另一台已授权设备撤销旧 Device ID，并立即轮换 Workspace key：

```bash
vgen identity revoke <旧_device_id>
vgen workspace key-rotate
```

当前 Alpha 已有 `identity recover --profile ...` 的底层恢复能力，但还不能一键重建 Home Broker、
默认 Workspace/Pool 和全部本地配置，因此本手册暂不把“新 Mac 一键迁移”标为完成能力。换机时
不要重新使用 Gateway Bootstrap code 创建第二个 User；应保留旧设备，直到新设备完成恢复、
key sync、Home Broker 绑定和真实任务验证后再撤销旧设备。

## 9. 安全边界

- 恢复词、私钥、Worker 私密 ZIP 和 Bootstrap code 都不能进入聊天、截图、Issue、日志或
  公开存储；
- 公网只暴露 Gateway HTTPS，不暴露 Gateway 内部端口或 ComfyUI；
- Gateway 保存任务状态、密文和调度元数据，不保存解密私钥；真正执行任务的 Worker 必然能
  看到该任务的 prompt、参数和媒体明文，因此只把任务调度到可信 Worker；
- User 加入时必须核对加入方本机显示的五组码；Gateway 不能引入一个从未被 Owner 签名接纳的
  新密钥。当前版本尚无签名成员透明日志，Gateway 仍可能重放过去确由 Owner 接纳过的旧成员
  集合；成员撤销后应立即轮换 Workspace key，并保持 Gateway 和客户端在可信网络状态下完成；
- 由 0.2.2 升级且没有 Owner pin/signed genesis 的既有 Workspace 会先拒绝密钥管理。Owner
  需要运行 `vgen workspace owner-migrate`，逐项核对屏幕上的 Gateway、Workspace、User 和
  root key ID，再输入 `MIGRATE-LEGACY-OWNER`。这是一次 legacy TOFU 边界；之后 pin 不允许被
  Gateway 替换。不要为了省一步而在交互终端使用 `--accept-legacy-tofu`；
- API Service 当前可以认证和获得 scope，但不会新获发 Workspace Data Key，不能读取 E2EE
  任务内容；不要把“Service 已注册”理解成加密任务链路已经开放；
- 模型任务只允许本机策略中固定的来源、revision、许可证、路径、大小和 SHA-256；
- Worker 更新不是任意远程 shell，但它会部署代码，只能授权可信 Broker 并使用可信 wheel；
- 不要为了排障手工删除数据库、密钥、模型冲突文件或旧 runtime，先保留日志和状态。

## 10. 常见故障

| 现象 | 处理 |
|---|---|
| `--domain is required` | 在每个 Gateway 脚本动作后明确加 `--domain <域名>`，域名不带 `https://` |
| 公网 `/api/v1/health` 失败 | 在 ECS 运行 `sudo ./setup-gateway.sh status --domain <域名>`；未恢复健康前不要初始化客户端 |
| Nginx 切换后持续 502 | 本机 Gateway 已健康且脚本明确回滚路由时使用 `activate --domain <域名>`；否则先检查 systemd/Nginx，必要时 `rollback --domain <域名>` |
| Mac 已有身份却再次要求 Bootstrap | 立即停止，不要创建第二个身份；先运行 `vgen profile show` |
| Windows 找到多套 ComfyUI | 在窗口中选择正确实例；没有目标时进入手动模式并粘贴应用或数据目录 |
| Desktop 自定义 data root 无法识别 | 按提示粘贴数据目录，或显式传 `-ComfyUIDataRoot`；不要把代码目录硬当数据目录 |
| ComfyUI 版本低于 `0.30.0` | 在 Desktop 执行 `Menu → Help → Check for Updates`，更新后完全退出 Desktop，再重启 Worker |
| GitHub clone 出现 `Connection was reset` | 保留 `%LOCALAPPDATA%\VGen` 后重新运行 `start-worker.cmd`；新 Worker 会先复用其中严格校验通过的旧 VGen custom nodes，本机确实没有合格副本时才需要恢复 GitHub 网络 |
| 本地复用后出现 `Filename too long` | 换用包含 Windows 长路径修复的 Worker ZIP，重新解压后运行 `start-worker.cmd`；无需删除 `%LOCALAPPDATA%\VGen`、旧 Worker 节点或模型 |
| 清理 `pack-*.idx` 时出现“访问被拒绝” | 换用修复后的 Worker ZIP 并重新运行；安装器会在确认暂存目录确属 VGen 且不含重解析点后清除只读属性并短暂重试，不要手工删除整个 `%LOCALAPPDATA%\VGen` |
| Python/Git 路径中混入 pip 或 winget 输出 | 换用修复后的 Worker ZIP 后直接重跑 `start-worker.cmd`；不要手工删除 `%LOCALAPPDATA%\VGen\worker-runtime-*`，安装器会把安装进度与返回路径分离 |
| Worker 显示 `maintenance-only` | 保持 PowerShell 窗口在线，在 Mac 发起 `vgen broker model-install ... --wait` |
| 提交前不确定 Worker 是否可用 | 运行只读的 `vgen task preflight`；按输出的 offline/busy、capability 或 rate 原因处理后重试 |
| CLI 报告 Worker 没有 manager Broker | 运行 `vgen worker manager-set "Windows GPU Worker"` 后重试维护任务 |
| `340001 LICENSE_APPROVAL_REQUIRED` | 在 Broker CLI 明确输入或传入所显示的许可证标识 |
| `340003 DISK_SPACE_INSUFFICIENT` | 释放最终模型文件及临时下载所需空间后重试 |
| `340004 PATH_CONFLICT` / `340005 DIGEST_MISMATCH` | 人工检查冲突路径；Worker 不会自动覆盖或删除异常文件 |
| Worker 更新后无法上线 | 保持前台监督器运行，等待自动回退；保留上一 runtime 和日志，不要强删 |

脚本的当前精确参数可以分别查看：

```bash
./setup-gateway.sh --help
vgen --help
vgen broker --help
vgen worker --help
```

Windows 安装器参数可在解压目录运行：

```powershell
Get-Help .\setup-worker.ps1 -Detailed
```
