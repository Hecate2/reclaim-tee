# TokenHive C4：真实 TEE 上线核对清单

日期：2026-09-03
状态：完成（C4，本地全栈仿真规划的最后一段）

本文件是《TokenHive 改造计划：连接驻留 TEE 与本地全栈仿真.md》第 8 节（切换到真实云 TEE）核对清单的逐项落账：每一项给出**代码位置**、**当前本地仿真的做法**、**云上装配要翻转的开关**与**验收方式**。C4 的立场与计划一致——不在本机执行真实 SEV-SNP（Apple silicon 无 AMD 安全处理器），只保证业务代码与装配层在本地仿真中全量执行、云上部署只改装配不改逻辑。

---

## 0. 装配层的地基：新增组件只依赖抽象

C1–C3 引入的全部新组件（ChannelManager、ProviderRegistry、流模式服务端、Hub 用户面 API）只依赖 `platform.Adapter` / `platform.Epoch` 抽象与标准库，不含任何「仿真 vs 真实」分支逻辑。装配差异集中在 `cmd/tee` 一个文件里——这正是「本地模拟 → 云上真实 TEE」只需翻开关、不需改代码的结构性前提。

- `tokenhive/platform/platform.go`：`Adapter`（`ServerTLSConfig / Snapshot / Refresh / Healthy`）与 `Epoch`（`Identity / Sign`）接口。
- `tokenhive/platform/simulated/`：软件证明适配器（证据字段与真实 SEV-SNP report 一一对应，只换信任根）。
- `tokenhive/platform/sevsnp/`：AWS SEV-SNP RA-TLS 适配器（已通过 `//go:build !mobile` 独立编译与单测）。
- `tokenhive/cmd/tee/main.go` + `epoch_default.go` / `epoch_sevsnp.go`：装配开关所在。

---

## 1. 核对清单逐项落账

### 1.1 签名 Epoch 改由 sevsnp 适配器的 Snapshot 提供

| 项 | 内容 |
|---|---|
| 计划原文 | 签名 Epoch 改由 sevsnp 适配器的 Snapshot 提供 |
| 代码位置 | `platform/sevsnp/adapter.go`：`Adapter.Snapshot(ctx) (platform.Epoch, error)`；`epoch` 实现 `Identity`/`Sign`。`proof.NewSigner(epoch)` 用 Epoch 签名 |
| 本地仿真现状 | `cmd/tee` 默认 `-platform simulated` → `epoch_sim.go` 的 `buildSimulatedEpoch()`（软件 key + 自描述证据） |
| 云上装配开关 | `cmd/tee -platform sevsnp`。该分支在 **epoch_sevsnp.go**（`//go:build sevsnp`）：`sevsnp.NewAWS(ctx, Config{Role: envOr("TOKENHIVE_TEE_ROLE", "tokenhive-tee")})` → `adapter.Snapshot(ctx)` 取 Epoch |
| 为何用 build tag | 真实适配器链路会引入 AWS 客机工具链与 go-sev-guest（其包级 `flag.Bool("workaround_kds_productname")` 会污染 CLI 帮助）。本地仿真二进制保持轻量干净；云上 `go build -tags sevsnp` 编译进真实链路 |
| 验收 | `go build ./tokenhive/cmd/tee/`（默认，模拟）与 `go build -tags sevsnp ./tokenhive/cmd/tee/`（真实装配）均编译通过；`-platform sevsnp` 在非 SEV-SNP 主机上快速失败并给出可读错误，而非静默降级 |

### 1.2 Hub 与 TEE 之间启用 mTLS（适配器的 ServerTLSConfig）

| 项 | 内容 |
|---|---|
| 计划原文 | Hub 与 TEE 之间启用 mTLS（适配器的 `ServerTLSConfig`） |
| 代码位置 | `platform/sevsnp/adapter.go`：`ServerTLSConfig()` 返回 RA-TLS 服务端 TLS 配置，证书签发接 `Healthy()` 门禁（不健康时 fail-closed，返回 `ErrNotReady`） |
| 本地仿真现状 | Hub↔TEE 走明文 HTTP（`cmd/hub` 的 `HTTPTEE`、`cmd/tee` 的 `ListenAndServe`）；凭证隔离不依赖这层——Hub 本来就不持有凭证，此通道承载的是已解密业务字节 |
| 云上装配方式 | TEE 监听器改用 `adapter.ServerTLSConfig()` 并开启 `ClientAuth: RequireAndVerifyClientCert`（Hub 侧持 RA-TLS 客户端证书）；同时可在 `tee.Config.SubmitterVerifier` 挂应用级 Hub 身份校验（预留插槽，见 `tokenhive/tee/service.go`） |
| 验收 | 部署核对：TEE 端口扫描无明文监听；Hub 无证书时握手失败；未受信任客户端无法到达 `/v1/execute` 与 `/v1/session` |

### 1.3 attestation evidence 的取回接口补齐（P0 缺陷）

| 项 | 内容 |
|---|---|
| 计划原文 | attestation evidence 的取回接口补齐——既有 P0 缺陷：回执默认不含证据时无法离线验证，属切换清单一部分 |
| 代码位置 | `proof/receipt.go`：`AttestationRef` 含 `EvidenceHash`（键 6）与可选 `Evidence`（键 7）；`proof.VerifyOptions.RequireEvidence`。`Signer.IncludeEvidence` 决定每张回执是否内嵌证据 |
| 本地仿真现状 | `cmd/tee` 默认 `-evidence true`（`Signer.IncludeEvidence=true`），每张回执自包含证据，离线验签无需外部缓存——这是仿真对 P0 的刻意规避 |
| 云上装配开关 | `cmd/tee -evidence=false`：回执只带 `EvidenceHash`。配套需要证据缓存/取回服务：verifier 凭 `(platform, application_id, evidence_hash)` 从 TEE 的证据接口取回原始 evidence 后走 `simulated.CheckEvidence` 同构的真实校验路径（SEV-SNP 侧为硬件签名链验证） |
| 验收 | 生产部署上线前必须存在证据取回端点（或等价的不可变证据广播），否则 `IncludeEvidence=false` 的每张回执都验不了——此条在计划中记为 P0，C4 将其显式列入上线 gate |

### 1.4 Channel 的 TLS 根证书从测试 CA 换为系统根

| 项 | 内容 |
|---|---|
| 计划原文 | Channel 的 TLS 根证书从测试 CA 换为系统根（生产上游是真实的 OpenAI 证书链） |
| 代码位置 | `transport/channel.go` `dialTCP`：`TLSClientConfig == nil` 时使用系统信任库（`RootCAs` 为空即系统根），仅当非 nil 时叠加自定义根池 |
| 本地仿真现状 | `cmd/tee` 默认 `-platform simulated`：从 `.sim/ca.pem`（mockprovider 自建测试 CA）加载根池，保持仿真密闭 |
| 云上装配开关 | `cmd/tee -platform sevsnp`（或显式 `-ca ""`）：`upstreamTLSConfig` 返回 nil → 系统信任库。mockprovider 被真实 api.openai.com 等替换后证书链自然成立 |
| 验收 | 生产 TEE 不信任任何测试 CA；`ChannelConfig.TLSClientConfig` 缺省即系统根，无自定义 CA 时不会 panic（见 C1–C3 审查修复的第 5 条） |

---

## 2. 装配开关速查表

| 开关 | 本地仿真 | 云上真实 TEE | 所在文件 |
|---|---|---|---|
| `-platform` | `simulated`（默认） | `sevsnp`（需 `-tags sevsnp` 编译） | `cmd/tee/main.go`；分支在 `epoch_default.go` / `epoch_sevsnp.go` |
| `-evidence` | `true`（默认，回执自包含） | `false` + 证据取回服务（§1.3 P0） | `cmd/tee/main.go` → `signer.IncludeEvidence` |
| `-ca` | 空 → 仿真自动加载 `.sim/ca.pem` | 空 → 系统信任库；或显式指定 PEM | `cmd/tee/main.go` `upstreamTLSConfig` |
| Hub↔TEE mTLS | 明文 HTTP | `adapter.ServerTLSConfig()` + 客户端证书校验 | `platform/sevsnp/adapter.go`（装配在部署层） |
| 证据取回 | 不需要（证据内嵌） | 必须补齐（P0，部署层） | `proof/receipt.go` 字段已就位 |

## 3. 代码路径核对结论

C4 不需要、也不应在本地执行真实 SEV-SNP。核对结论：

1. 新增业务/连接代码对平台选择完全无感：全部走 `platform.Epoch` 抽象，`cmd/tee` 是唯一的装配点。
2. 三个装配开关（platform / evidence / ca）默认值逐一保持仿真行为，harness 1–15 全绿不受影响。
3. `sevsnp` 适配器自身已有单测（`platform/sevsnp/adapter_test.go`），真实硬件验收留待 AWS c6a/m6a CI nightly，与本机边界一致。

（本文件只落账核对清单；既有「已完成的 S1–S5」「C1–C3」文档与本文件无冲突，C1–C4 文档族共同构成装配与验收记录。）
