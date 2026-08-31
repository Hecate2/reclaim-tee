# TokenHive 改造路线图

从 `reclaim-tee` fork 到可运行的 TokenHive Trusted TLS Proxy。

配套文档：[TokenHive 基于 TEE 的可信 AI API 代理方案](./TokenHive%20%E5%9F%BA%E4%BA%8E%20TEE%20%E7%9A%84%E5%8F%AF%E4%BF%A1%20AI%20API%20%E4%BB%A3%E7%90%86%E6%96%B9%E6%A1%88.md)

---

## 关键决策：不裁剪 Reclaim 原代码

**Reclaim 的既有代码（`tee_t/`、`mpc/`、`oprfmpc/`、`circuits/`、`formal/`、`minitls/` 等）全部原样保留，不做删除或改造。** TokenHive 的全部新增代码放在 `tokenhive/` 目录下，与 Reclaim 代码并存。

带来的后果：

- 优点：保留完整 git 历史与上游同步能力；`minitls/`、`shared/`、`client/`、`providers/` 等底座可以按需直接引用，不必复制一份；随时能回到 Reclaim 的实现做对照。
- 代价：仓库体积（尤其 `circuits/` 约 73MB）和依赖数量不会缩减；`go build ./...` 仍会编译 MPC/ZK 相关包。日常开发用 `go build ./tokenhive/...` 限定范围即可。

---

## 关键决策：User 侧默认信任 Hub（2026-08-30）

**JobSpec 不再需要 User 签名，也不引入本地 sidecar 代理（`tokenhive/agent/`）。** User 用标准 AI SDK 直接访问 Hub，由 Hub 构造并提交 JobSpec。

**Provider 侧的信任假设不变** —— Provider 仍不信任 Hub。因此以下全部保留：

- 凭证隔离在 TEE，Hub 全程只见 TLS 密文
- Provider Policy，Hub 无法越权调用
- TEE 签名回执，作为 Provider 的审计凭据

变化的只有回执的受众：从「User 防范 Hub」转为「Provider 审计凭证使用」。

**该未决项已于 2026-08-31 定案：采用传输层 mTLS，不做应用级 Hub 签名。** 论证：回执受众是 Provider（§17），而 Provider 关心的「凭证是否被越权使用」由 Policy（§8）+ 回执签名（§17）完整保证，两者都不依赖 Hub 身份——即 Hub 身份对 Provider 侧的安全保证贡献为零。为它维护一整套公钥注册，买到的是审计便利而非安全性。`tee.Config.SubmitterVerifier` 保留插槽备用。详见方案文档 §7。

**代码已同步（2026-08-30）**：`jobs.SignUserSignature` / `VerifyUserSignature` 与 `Spec.UserKeyID` 字段连同 `tokenhive/jobs/signature.go` 一并删除。保留一套没有调用方、语义还是错的签名代码，比将来按需重写更贵——若最终选「Hub 签 JobSpec」，那是一套新的提交者语义（含 Hub 公钥注册），不该复用 User 的壳子。`platform.SigningDigest` / `VerifySignature` 这条签名底座仍在，随时可重建。

---

## 现状盘点（2026-08-31）

已完成：

- 方案定稿：TEE 作可信 TLS Client + Provider Agent 作 TCP Egress，放弃 MPC/ZK 双 TEE 架构
- `tokenhive/platform/` — 平台抽象层（Identity / Epoch / Adapter、domain-separated 签名与验证）+ AWS SEV-SNP 适配器
- `tokenhive/internal/canonical/` — RFC 8949 确定性 CBOR 编码与抗变形解码
- `tokenhive/jobs/` — JobSpec schema、canonical 编码与 `job_spec_hash`、`body_hash` 绑定校验、nonce/expiry、保留头校验。不含任何签名：User 不签，Hub 的通道认证已定传输层 mTLS
- `tokenhive/policy/` — Provider Policy schema、段级路径匹配、Authorize 决策、Provider 签名、PolicySet 热更新
- `tokenhive/proof/` — ExecutionReceipt、streaming hasher、TEE signer、独立 verifier
- `tokenhive/tee/` — 服务主体：`Service.Execute` 按固定顺序执行检查、注入凭证、流式摘要、签回执；`Transport` / `CredentialSource` 抽象把网络与密钥存储隔离在接口后
- `tokenhive/transport/` — `tee.Transport` 的 HTTP 实现：HTTP/1.1 + HTTP/2、Keep-Alive、SSE 逐 chunk 转发；显式关闭透明 gzip / 静默重试 / 跟随重定向 / 环境变量代理四个会破坏回执契约的标准库行为；SOCKS5 dialer（TEE 侧隧道端点）
- `tokenhive/provider/` — Provider Agent：SOCKS5 CONNECT-only server + 目标白名单 + RFC 1929 鉴权（constant-time 比较），纯字节 pipe 不检查转发内容
- `tokenhive/integration/` — 跨包链路测试 + E2E：mock provider（SSE）→ Provider Agent 隧道 → HTTP transport → `tee.Service` 全链路，含链路中断场景

剩余未开始：OAuth Vault（M3）、实机部署（M3）。

---

## M0 · 决策与准备（已完成）

| 议题 | 结论 |
|------|------|
| License | **不作为阻断项**（用户 2026-08-30 确认）。上游 `reclaim-tee` 无明确 License，商用前仍需自行评估，但不阻塞开发。 |
| 目标平台 | AWS SEV-SNP。已有 `tokenhive/platform/sevsnp/` 适配器；GCP Confidential Space 留作后期。 |
| 目录 | 在**本仓库内**新增顶层目录 `tokenhive/`，不新建仓库、不裁剪既有代码。 |

---

## M1 · 裁剪（已取消）

原计划删除 `tee_t/`、`mpc/`、`oprfmpc/`、`circuits/`、`formal/` 等目录。按上述决策取消，这些目录保持原样。

---

## M2 · 单 TEE 核心链路（已完成 2026-08-31）

目标：打通 `Hub → TEE → Provider Agent → OpenAI` 的最小可信链路。

1. ✅ **`tokenhive/jobs/`** — JobSpec schema（canonical 编码 + `job_spec_hash`）、`body_hash` 绑定校验、nonce/expiry、保留头校验。~~User 签名验证~~ 已按新信任模型删除
2. ✅ **`tokenhive/policy/`** — Provider Policy（hosts / path rules / methods / query 白名单 / 凭证注入 / 限额）与 Authorize 决策
3. ✅ **`tokenhive/proof/`** — ExecutionReceipt（RFC 8949 deterministic CBOR）、streaming hasher、TEE signer、独立 verifier
4. ✅ **`tokenhive/integration/`** — 跨包链路测试：JobSpec → Policy 授权 → 执行 → 回执验证，锁住包与包之间的接缝
5. ✅ **`tokenhive/tee/`** — 服务主体：接收 Job → **Hub 通道认证（已定：传输层 mTLS，`SubmitterVerifier` 插槽留空）** → JobSpec 结构校验 + `body_hash` 绑定 → Policy check → 注入凭证 → 发起请求 → 流式摘要 → 签回执。网络层抽象为 `Transport` 接口、凭证存储抽象为 `CredentialSource`，第一版提供内存实现，Vault 留到 M4
6. ✅ **`tokenhive/transport/`** — HTTP 层：不基于 `providers/`，而是包一层标准 `net/http`（连接池、Keep-Alive、h2 均由标准库提供），重点在显式关闭会破坏回执契约的四个默认行为：透明 gzip 解压（`DisableCompression`）、静默重试（无 `GetBody` 的不可重放 body，含无 body 请求）、跟随重定向（`ErrUseLastResponse`）、环境变量代理（`Proxy: nil`）。SSE 逐 chunk 转发接 `StreamingHasher`。另含 `SOCKS5Dialer`：TEE 侧把出站 TCP 隧道化到 Provider Agent，TLS 仍在 TEE 终结，Agent 只见密文
7. ✅ **`tokenhive/provider/`** — Provider Agent：SOCKS5 CONNECT-only（拒绝 BIND/UDP），RFC 1929 用户名密码鉴权（constant-time），**目标白名单强制非空**（空白名单 = 开放代理，直接拒绝构造）。不基于 `client/` relay——SOCKS5 是标准协议，比改造 Reclaim relay 更简单且客户端生态现成

验收（E2E demo）：本地起 TEE + Agent，User 经 mock Hub 发真实 OpenAI `/v1/responses` SSE 请求，流式收到全部 chunk，流结束后拿到 ExecutionProof，verifier 离线验签通过。篡改任一 chunk / body 与 JobSpec 错配 / 越权路径调用均被拒绝。

**验收达成（2026-08-31）**：`integration.TestEndToEndSSEThroughProviderAgent`（全链路 SSE + 回执验签 + transcript 比对 + 凭证不泄漏断言）与 `TestEndToEndMidStreamDisconnect`（链路中断 → truncated 回执仍可验签）。「篡改 chunk / body 错配 / 越权拒绝」分别由 `proof.MatchesStream`、`tee.ErrBodyMismatch`、`TestPolicyIsTheOnlyGuardOnHubCraftedJobs` 的既有用例守住。mock provider 用明文 HTTP 是有意的：它同时证明了 Agent 无法篡改转发内容（若能篡改，注入的 credential 或 body 就不会原样到达）。

---

## M3 · 凭据生命周期与安全闭环（1~2 周）

1. **`tokenhive/token/`** — OAuth Vault：Provider 经远程证明验证 TEE 后，通过加密通道上传 OAuth Token + Policy；TEE 侧落盘加密（复用 `shared/` 的 KMS 集成）；token rotation 接口
2. **Attestation 缓存与轮换**：`platform.Adapter.Snapshot/Refresh` 已有接口，补上「证据到期前后台轮换 + attestation_id 复用」，RA 不进每请求 hot path
3. **证明公钥绑定**：把 proof signing key 绑进 RA evidence（`tokenhive/platform` 的 Identity 已预留 Evidence/EvidenceHash 字段），verifier 校验 app hash + 公钥 + 有效期

验收：Provider 全新走一遍 onboarding → 上传凭证 → 发起 job → 撤销 token 的完整生命周期；Hub 在抓包中只见密文。

---

## M4 · 性能与生产化（2 周）

1. **TLS Connection Pool**：per (provider, host) 的连接池，SSE 长连接不回池、空闲回收
2. **Benchmark 套件**（方案 §18 的验收目标）：TTFT 开销 <1%、流式吞吐开销 <3%、receipt 生成 p95 <5ms、证明体积（带 attestation ref）<2KB
3. **运维**：复用 `deploy/` 可复现构建（image digest 即 enclave identity）；metrics / 日志接入 `shared/` 现有 GCP/AWS logging

---

## M5 · 扩展（按需）

TLS 连接池之外的：HTTP/2、多 Provider 路由、多区域 TEE + failover、OAuth refresh、更多 AI Provider（Anthropic / Gemini / xAI）、proof 锚定 transparency log。

---

## 已落地的设计约定

写代码时遵守，避免后续返工：

- **整数 CBOR 键**。所有进入哈希或签名的结构用 `cbor:"N,keyasint"`，键一旦发布不再改号。这样编码紧凑（当前回执 520 字节，远低于 2KB 预算），且不受字段重命名影响。
- **抗变形解码**。凡是从外部字节解码的签名结构，必须走 `canonical.Unmarshal`，它会重新编码并比对，拒绝非规范编码。
- **域分离复用**。`platform.SigningDigest(domain, payload)` 是所有签名的唯一摘要构造入口，各类签名共用同一条验证路径（`platform.VerifySignature`）。当前主线只用到 TEE 回执签名与 Provider 策略签名两种。
- **废弃键不复用**。JobSpec 的 CBOR 键 14（原 `UserKeyID`）随 User 签名一并移除并**永久作废**：旧版本解码器仍可能发出该键，重新分配给别的字段会被误读。新字段从 15 起。同类结构照此办理。
- **哈希域常量跟着用途改名**。`JobSpecSigningDomain` 已更名 `JobSpecHashDomain` —— 它现在只做哈希的域分离前缀，不再用于任何签名。值未变，因此 `job_spec_hash` 的计算结果不变。
- **响应摘要不含分帧**。`SHA-256("TokenHive.Response.v1" || job_id || body)` 只覆盖字节流，SSE 重新分帧不影响摘要；ChunkCount / ResponseBytes 靠回执签名保证。
- **签名者覆盖 attestation**。`proof.Signer.Sign` 会用当前 epoch 覆写调用方传入的 attestation，杜绝「回执声称一个身份、实际用另一个密钥签名」。
- **策略签名自证**。`SignPolicy` 会用签名密钥的公钥覆写 `Policy.ProviderKey`，策略因此自带验签公钥，不需要外部注册表；`PolicySet.Add` 只在验签通过后才装载。
- **跨包规则不复制**。provider 名与 TEE 保留头的判定由 `jobs` 导出（`ValidateProviderName` / `IsForbiddenHeader`），policy 直接复用，避免两份规则各自漂移。
- **回执绑定策略**。`Receipt.PolicyHash` 记录执行时依据的 Provider Policy，否则回执只证明「某个 enclave 产生了响应」，证明不了「它守住了凭证主人划的边界」。
- **验签通过不等于覆盖了这份请求**。回执里可读的 Host / Path / Method 只是描述性副本，会被签名但说明不了 TEE 拿到的是哪份 spec。验证者必须在验签后**再比对 `job_spec_hash`**，两步缺一不可（`integration.covers` 就是这个检查的参考实现）。

---

## 风险清单

| 风险 | 等级 | 对策 |
|------|------|------|
| License 未确认 | 低（用户已确认不阻断开发） | 商用发布前再评估 |
| 与 Reclaim 代码并存导致构建变慢 | 低 | 日常用 `go build ./tokenhive/...` 限定范围；CI 再跑全量 |
| minitls 无 Keep-Alive 实践 | 低（已不适用） | M2 最终方案未用 minitls：`tokenhive/transport/` 直接用标准 `net/http` 连接池，Keep-Alive/h2 开箱即得 |
| SEV-SNP base image 变更 | 中 | 已有 `deploy/image-history.json` digest 锚定机制 |
| Provider 断流/恶意 drop | 低（可用性问题） | `completion_state` 显式签入回执，证明完整性即可 |
| Hub 缺少应用级身份认证 | 低 | **已定案（2026-08-31）**：采用传输层 mTLS。Hub 身份对 Provider 侧保证零贡献（Policy + 回执已覆盖），故不引入公钥注册。`tee.Config.SubmitterVerifier` 为将来审计需求留插槽 |
| Hub 越权使用 Provider 凭证 | 中 | Provider Policy 是此时唯一约束，必须在 `tee/` 中强制前置，不可做成可选。移除 User 签名后这一点从「重要」升为「唯一防线」，由 `integration.TestPolicyIsTheOnlyGuardOnHubCraftedJobs` 守住 |

---

## 建议的下一个动作

M2 已全部完成。M3 按依赖顺序：

1. **Hub↔TEE 服务面** — 把 `tee.Service` 挂到监听器（gRPC 或 HTTP），Hub↔TEE 通道启用 mTLS（自签 CA 起步）；这是 `SubmitterVerifier` 之外的另一半：TEE 进程的输入侧目前只有测试驱动
2. **`tokenhive/token/`** — OAuth Vault：Provider 经远程证明验证 TEE 后上传凭证 + Policy
3. **Attestation 轮换 + 证明公钥绑定** — `platform.Adapter.Snapshot/Refresh` 已有接口，补后台轮换
4. **AWS SEV-SNP 实机部署** — 复用 `deploy/` 可复现构建，image digest 即 enclave identity
