# TEE / Hub 证书有效期审计与长寿命部署方案

> 状态：**只做诊断，未改动 Hub 或 TEE 机器**。本文是提案。
> 对象：Hub `52.215.235.214`（`i-018b872fa8ecdefc8`, priv `10.0.1.151`）、TEE `10.0.1.63`（`i-0393503927c542557`），region `eu-west-1`。

---

## 1. 结论（TL;DR）

1. 那条警告**不是无害的**。它的含义是：Hive 无法再通过 RA-TLS 验签 TEE，因此**拿不到 TEE 的 inbox 公钥**，provider 无法把凭据封装给 TEE —— 走真实 TEE 的 supply 链路是断的。进程不崩（只是 `Warn` + 反复重试），所以表现为"静默降级"。
2. 根因是 **AWS 签发的 NitroTPM 叶证书只有 3 小时有效期**，而 TEE 的 RA-TLS 证书在**进程启动时只签发一次、之后永不刷新**，把这份 3 小时的证据一直挂在证书里。于是**每次 TEE 启动约 3 小时后，任何做日期校验的验证方都会拒绝它**。
3. 因此"把证书有效期调长"这个思路**对这条链无效**：3h / 24h / 6d / 20d 这几张都是 AWS 签发的，你改不了。唯一有效的杠杆是让 TEE **在最短的那张证书过期前重新出证（re-attest 并重签 RA-TLS）**。这个机制代码里**已经写好但没接线**。
4. 好消息：其余你自己可控的证书（mTLS CA/叶、Secure Boot 密钥、GCP vTPM CA、内嵌 Nitro 根）都已经是"十年级"，不需要动。

---

## 2. 警告的完整链路（代码级）

```
Hive 启动
 └─ cmd/hive/main.go:82   inboxSource → source(startup)   // GET https://10.0.1.63:18090/v1/credential-key
     └─ teeclient/deployment.go:82  VerifyPeerCertificate = shared.VerifyRATLSPeer(...)
         └─ shared/ratls_verifier.go:136  fmt.Errorf("ratls: %w", err)
             └─ shared/secure_boot.go:213  fmt.Errorf("SEV2 prerequisite: %w", err)
                 └─ shared/snp_combined_aws.go:217  verifyNitroTPMDocument(env.NitroTPM)
                     └─ shared/snp_combined_aws.go:338  verifyNitroChain(leaf, cabundle)
                         └─ :380  leaf.Verify(x509.VerifyOptions{Roots: [内嵌 Nitro 根]})
                             ⇒ x509: certificate has expired or is not yet valid
```

- 失败在 `main.go:82`，是 `slog.Warn(...)`，**不是** `return err` → Hive 继续跑（实测 PID 77036 存活）。
- 但 `main.go:101` 的 `ConfigureDynamicSupply` → `supplyChannel()`（`internal/service/supply.go`）**只做配置校验、不连 TEE**，所以进程"看起来正常"，实际 TEE 通道是坏的。
- `InboxSource()` 每次调用都会重新握手重试 → **每次都会失败**（"Hive will keep asking" 但永远拿不到）。

**两侧验证的差异（重要）**：

| 验证方 | 代码 | 会不会查 NitroTPM 链日期 | 会不会查 RA-TLS 叶日期 | 实际失效点 |
|---|---|---|---|---|
| Hive（市场 Hub） | `VerifyRATLSPeer` | 会（`leaf.Verify`） | 不会 | **3h** |
| tokenhive hub (`-mtls-ca`，默认 pin 模式) | `ClientMTLSConfig` (`internal/mtls/mtls.go`) | 不会 | 会 | **24h** |
| tokenhive hub (`-tee-verify=attestation`，见 §7) | `VerifyRATLSPeer` | 会（`leaf.Verify`） | 不会 | **3h** |

所以 3h～24h 之间是"只有 Hive 坏、tokenhive 侧还好"；超过 24h 两边都坏。
切到 `-tee-verify=attestation` 后，tokenhive 侧与 Hive 同构（都受 3h NitroTPM 链约束），
于是 §5 方案 A 的刷新对**两个**验证方同时生效，24h 台阶消失。

---

## 3. 全证书清单（含实测有效期）

### 3.1 TEE 的 RA-TLS 证书链（实测自 `openssl s_client 10.0.1.63:18090` 抓到的活体证书）

| 证书 | 签发者 | notBefore | notAfter | 有效期 |
|---|---|---|---|---|
| RA-TLS 叶 `CN=tokenhive-tee` | 自签 | 09-17 09:23 | 09-18 10:23 | 24h（当时实测；**自签叶代码已改为 5y，见 §8**） |
| **NitroTPM 叶** `i-0393…-tpm….aws` | AWS NSM | 09-17 10:23:15 | **09-17 13:23:18** | **3h00m03s ← 已过期，就是它** |
| Nitro 实例中间 CA | AWS | 09-17 10:22 | 09-18 10:22 | 24h |
| Nitro zonal 中间 CA | AWS | 09-17 04:28 | 09-22 23:28 | ~6d |
| Nitro regional 中间 CA | AWS | 09-16 00:52 | 10-06 01:52 | 20d |
| Nitro 根（内嵌 pin） | AWS | 2019-10-28 | 2049-10-28 | ~30y |

### 3.2 仓库内你自控的证书

| 文件 | 主体 | 有效期 | 评价 |
|---|---|---|---|
| `tokenhive/cloudtest/snp/.certs/hub-ca.pem` | `CN=tokenhive-mtls-ca` | 09-17 → **2036-09** | 10y ✅ |
| `.certs/hub-cert.pem` | `CN=tokenhive-sim-hub` | 09-17 → **2031-09** | 5y ✅ |
| `.certs/mp-ca.pem` | `CN=tokenhive-sim-provider-ca` | 09-17 → **2036-09** | 10y ✅ |
| `.certs/mp-cert.pem` | `CN=tokenhive-sim-provider` | 09-17 → **2031-09** | 5y ✅ |
| `.certs/hub-ca.key` / `mp-ca.key` | CA 私钥 | — | ✅ 保留用于免重建重签 |
| `.certs/tee-cert.pem` | `CN=tokenhive-tee` | 09-16 → **09-17（已过期）** | ⚠️ 陈旧副本（旧 TEE 的），仅本地留存 |
| `deploy/secure-boot/PK.crt`, `KEK.crt` | Reclaim Secure Boot | 2026-08 → **2036-08** | 10y ✅ |
| `deploy/secure-boot/R.crt` | Reclaim Cross-Cloud Release Key | 2026-09 → **2046-09** | 20y ✅ |
| `shared/aws_nitro_root.pem` | `CN=aws.nitro-enclaves` | 2019 → **2049** | 30y ✅ |
| `shared/gcp_vtpm_ca_{root,intermediate}.crt` | Google EK/AK CA | 2022 → **2122** | 100y ✅ |

### 3.3 Hub 机 `/etc/tokhive/`

| 文件 | 主体 | 有效期 | 说明 |
|---|---|---|---|
| `hive-client.pem` | `CN=tokenhive-sim-hub`（由 tokenhive-mtls-ca 签） | 09-17 → **2031-09** | ✅ 与 `.certs/hub-cert.pem` 同源 |
| `hive-client-key.pem` | — | — | ✅ |
| `hub-ca.pem` | `CN=tokenhive-mtls-ca`（自签根） | 09-17 → **2036-09** | ✅ |
| （无 `mtls/tee-cert.pem`） | — | — | 同事遇到的"找不到 pem"即此：该路径是 `crosshost.sh` 在 `cd ~` 下的相对路径 |

> 注：`ssh-key.pem`、`*.pub.pem`、`*-key.pem` 不是证书，无有效期。

---

## 4. 根因：3 小时悬崖

> 本节描述的是 **§7 接线之前**的形态（当时 tokenhive 侧没有刷新调用者）。§7 已接上刷新循环；
> 接上之后的剩余缺陷（准入 margin 比 AWS 的重签提前量长）见 §10。

两部分叠加：

1. **AWS 侧不可控**：NitroTPM 出证时，AWS NSM 签发的叶证书 **TTL 仅 3 小时**（本次实测 3h00m03s；中间 CA 也都是 24h/6d/20d 级别）。
2. **TEE 侧可修**：`shared.NewRATLSManager` 在**进程启动时**签一张 24h 的自签 RA-TLS 叶，并把**那一刻**的出证证据（含那张 3h 的 NitroTPM 叶）塞进证书扩展 `.2`。之后：
   - `tokenhive/platform/sevsnp/adapter.go` 的 `GetCertificate` 返回**启动时钉住的**快照；
   - `Adapter.Refresh()` / `sharedManager.Refresh()` **存在但没有任何生产调用者**（`tokenhive/` 内除了测试，无人调用）。

   → **TEE 启动 3 小时后，证书里的 NitroTPM 叶过期，Hive 验签开始失败，直到 TEE 重启。**

**已经写好的正确机制（reclaim-tee 侧在用，tokenhive 侧当时没用）**：

- `shared/router_runtime.go` 的 `SNPAdmissionDeadline()` / `SNPSigningDeadline()`：两者都取自 NitroTPM 叶的
  `NotAfter` —— 前者就是 `NotAfter` 本身（验证方停收的时刻），后者是 `NotAfter − SNPSigningMargin`（5 分钟）。
  <br>（2026-09-22 变更，见 §10。当时这里是单个 `SNPAttestationExpiry() = NotAfter − SNPRefreshMargin(30min)`，
  那个 30 分钟正是 §10 那条黑窗的成因。）
- `shared/router_runtime.go` 刷新循环：按 `clamp(Until(签名截止), 下限 minRefreshFloor, 上限 RATLSRefreshIntervalSNP=2h)` 定时 `ratls.Refresh(ctx)`。

即：设计意图本来就是"跟着 AWS 的 3h 走、提前换证"，只是 tokenhive 的 TEE 没接这条线。

---

## 4.5 24 小时台阶：实例中间 CA 与 RA-TLS 叶各自的影响

### A. RA-TLS 叶（`CN=tokenhive-tee`，TEE 自签，boot+24h）
按"是否做标准链校验（含日期）"分类：

| 客户端 | 代码 | 查对端叶日期？ | 24h 之后 |
|---|---|---|---|
| tokenhive hub → TEE(18090) | `internal/mtls/mtls.go:88` `ClientMTLSConfig` → `leaf.Verify(Roots=pin)` | **查** | **新建握手失败**：`tee certificate is not pinned: x509: certificate has expired` |
| Hive → TEE(18090) | `VerifyRATLSPeer` | 不查 | 不受影响（它 3h 就坏了） |
| TEE 自己 | Go TLS server + `GetCertificate` | 不查自己 | 无感，照旧发出过期叶 |
| 已建立的 TLS 连接 | — | 只在握手时校验 | **不中断**，可跨过 24h |
| 其它标准客户端（`curl --cacert` 不带 `-k` 等） | 标准校验 | 查 | 被拒 |

当前部署里唯一的此类客户端 = `tokenhive/cloudtest/snp/crosshost.sh:383-384` 给 `./tee/hub` 的
`-mtls-ca mtls/tee-cert.pem`（hub 作为 client 调 TEE 的 `/v1/execute`、`/v1/receipts` 等）。

**⚠️ 连带风险（比 24h 更容易踩到）**：这个 pin 是 `buildTEEClientTLS()` → `LoadCAPath()`
（`tokenhive/cmd/hub/main.go:411-427`）**启动时读一次**的静态锚。
→ TEE 一旦**重启或轮换 RA-TLS 密钥**，pin 立即失效（`not pinned`），**早于** 24h。
→ 反之：**TEE 换叶后，hub 必须重抓 `tee-cert.pem` 并重启**。这一点与 §5 方案 A 直接冲突（见该处 caveat）。

> **后续（2026-09-17，见 §9.2）**：三个真实部署调用点已从 `-mtls-ca` pin 切到 `-tee-verify attestation`，
> hub 不再钉具体证书，换叶/换密钥自动接受；pin 模式只保留给 simulated / harness。上述"连带风险"因此
> 只对"仍在用 pin 的部署"成立。

### B. Nitro 实例中间 CA（AWS 签发，`CN=i-0393…eu-west-1.aws.nitro-enclaves`，boot+24h）
- 它在 NitroTPM doc 的 `cabundle` 里，而 `verifyNitroChain` 的 `leaf.Verify` 校验**整条链**的日期。
- ⇒ **"只把 NitroTPM 叶换新"是无用的**：24h 时链依旧断。**必须在 24h 前重新出证整份 document**。
- 更长远：zonal CA ~6d、regional CA 20d 也会到期 ⇒ 不刷新的 TEE 会依次在
  **3h → 24h → ~6d → 20d** 四个台阶上继续失效（即使只修了叶）。

### C. 汇总：自 TEE 启动起算

| 时刻 | 到期证书 | 开始失败的一方 |
|---|---|---|
| 3h | NitroTPM 叶 | Hive（attestation 链日期） |
| 24h | Nitro 实例中间 CA | 所有做链校验的验证方（Hive 早已失败） |
| 24h | RA-TLS 叶 | tokenhive hub 的 `-mtls-ca` pin、标准校验客户端 |
| ~6d | Nitro zonal CA | 链校验（须重新出证） |
| 20d | Nitro regional CA | 链校验（须重新出证） |
| 2031 / 2036 | hub-cert / mTLS CA | 常规轮换，不紧张 |

**净结论**：3h 是最严约束，已自动覆盖 24h。24h 的意义在于——
**无论是"只换叶"还是"每天重启一次"，都不够**；必须**重新出证整份 document**（方案 A），
且必须同步处理 hub 的 pin（见下）。

---

## 5. 部署与操作方案

### 方案 A（推荐，唯一的根治）：给 tokenhive 的 TEE 接上 RA-TLS 刷新
- 在 `tokenhive/cmd/tee` 里，参照 `shared/router_runtime.go` 的循环调用 `adapter.Refresh(ctx)`：
  - 间隔 = `min(RATLSRefreshIntervalSNP(2h), SNPNitroLeafNotAfter(证书)−SNPRefreshMargin(30min))`。
    <br>（2026-09-22 起：瞄准 `SNPSigningDeadline = NotAfter − 5min`，下限 2min —— 见 §7.2 与 §10。）
  - 由于 NitroTPM 叶是 3h，实际节奏 ≈ **每 2h 或 ~2.5h 一次**，远早于 3h 悬崖。
- 一次改动同时解决两件事：
  - Hive 侧（3h，NitroTPM 链日期）—— 每次刷新都换一张新的 3h 叶；
  - tokenhive `-mtls-ca` 侧（24h，RA-TLS 叶日期）—— 刷新会重签叶证书。
- `Adapter.Refresh` 注释已声明"旋转 RA-TLS 密钥与证据、新握手使用新 epoch"，语义现成。
- **⚠️ 必须同时处理 hub 的 pin，否则会"修好 Hive、弄坏 hub"**：
  `Adapter.Refresh` 会轮换 RA-TLS **密钥**（`adapter.go:149`），而 hub 的 pin
  （`mtls/tee-cert.pem`）是**启动时读一次**的静态锚（`cmd/hub/main.go:411-427` → `LoadCAPath`）。
  TEE 一换叶，hub 就会以 `not pinned` 拒绝 TEE。三选一：
  - (i) hub 定期重抓 `tee-cert.pem` 并热重载 / 重启；
  - (ii) hub 改用 attestation 验证（`VerifyRATLSPeer` 同款：验证据 + SPKI 绑定 + `-expected-app`）**替代**钉具体证书——本来就能容忍换叶；
  - (iii) 让 TEE 的 RA-TLS 叶由**固定长期 CA** 签发，hub 钉该 CA（需改 `NewRATLSManager`，当前是自签叶）。

### 方案 B（测试期权宜）：定时重启 TEE
- 每 **< 3h** 重启一次 TEE（或触发一次重新出证）。零代码，但会打断进行中的会话与 inbox key。

### 方案 C（不建议）：放宽验证方
- 让 `verifyNitroChain` 不校验那张短命 AWS 叶的日期（只验 COSE 签名 + 链到内嵌根 + user_data/PCR/module_id 绑定）。
- 能绕过，但**削弱了新鲜度语义**（3h 窗口本身就是 AWS 表达的"这份出证有多新"）。除非明确只为临时联调，否则不建议动。

### 方案 D（保持非 AWS 证书长寿命，基本已完成）
- mTLS CA 10y / 叶 5y（已做）；如需进一步减少轮换，可把叶提到 10y。
- Secure Boot PK/KEK 10y、R 20y，GCP vTPM CA 100y、内嵌 Nitro 根 30y —— 都无需改。
- **纪律**：不要再把 24h 的一次性 fixture 烧进 AMI（上次 `.certs` 就是这么污染 bundle 的）；保留 `hub-ca.key` / `mp-ca.key`，以后换叶只需重签、不必重建 AMI。
- **代码已对齐（见 §8）**：`gencerts` / `EnsureMTLSCerts` 生成的那几张原本仍是 24h，现已改为 CA 10y / 叶 5y，与磁盘上的 `.certs` 一致；自签 RA-TLS 叶 24h → 5y。

---

## 5.5 方案 A 会让 provider 的 accessToken 被反复重新加密吗？——**不会**

因为这里有两把**互相独立**的密钥：

| 密钥 | 生成 / 轮换时机 | 代码 | 方案 A 轮换它吗 |
|---|---|---|---|
| RA-TLS 密钥 + 证据 | TEE 启动时；`Adapter.Refresh` 可轮换 | `platform/sevsnp/adapter.go:151` | **是** |
| 凭据 inbox 密钥（X25519） | **TEE 进程启动时一次**，私钥不落盘 | `cmd/tee/main.go:176` `tee.GenerateInboxKey()` | **否**（refresh 完全不碰） |

`Adapter.Refresh` 只重建 RA-TLS epoch（`Refresh` → `a.manager.Refresh` → `buildEpoch`）；
inbox 密钥是 `main.go:176` 单独生成、直接传给 `tee.NewService`（`:216`）的，与 refresh 路径无交集。

### 另外，"Hub 重新加密"这个动作在当前架构里本来就不存在
- **加密方是 provider agent 自己**：`provider/agent.go:363` `tee.EncryptCredential(pub, reg.Provider, a.cfg.Credential)`；
  公钥由 agent 经 Hub 中转取得（`agent.go:454` → `GET /v1/credential-key`）。
- **Hub 只中转公钥、只存密文**：`hub/hub.go:335-344`（"The Hub is only a relay"）、`hub/agentnet.go:117`（"The Hub only ever holds this ciphertext"）。
- **每个 job 只是把已存密文原样挂上**：`hub/hub.go:363-370` `attachCredential()` → `credentialStore.Get(provider)`，**不重新加密**。
- 唯一例外：`hub.go:346-361` `RegisterCredential` 是"无 agent 的一次性 Hub 直连 TEE"路径，Hub 代客封装一次——同样只加密一次。

### 什么时候才需要重新密封？**TEE 重启**（不是刷新）
- `cmd/tee/main.go:170-179`：inbox 私钥不持久化，"**a restart rotates the key** and agents re-register with the fresh public half"。
- `hub/tee.go:186-194`：Hub **故意不按 TTL 缓存** inbox key —— "the key rotates on every TEE restart"，缓存窗口内会把死钥匙发给重连 agent → "whose sealed envelopes the new TEE can no longer open"。

**这恰好是方案 A 优于方案 B 的核心理由**：
- **方案 A**（只轮换 RA-TLS、进程不重启）→ inbox 密钥不变 → **已封好的 envelope 持续有效，零重新加密**。
- **方案 B**（每 <3h 重启 TEE）→ inbox 每次都换 → **每次重启后所有 provider 都要用新公钥重新上报/密封一遍**。方案 B 的隐藏代价 = 周期性全量重密封。

### ⚠️ 方案 A 的两个实现注意点（不是加密问题，但实现时不能漏）
1. **刷新本身不产生不可用窗口**：`GetCertificate` 只在**当前 epoch 自己的证据**越过截止时刻时返回 `platform.ErrNotReady`（`adapter.go`），而轮换是一次原子替换 —— 旧 epoch 一直在服务，直到新的（把截止时刻推得更远的）epoch 顶上来。刷新耗时（NitroTPM + SEV 两次设备往返）落在旧证据仍然有效的区间内，所以没有"刷新期间新连接被拒"这回事。
   <br>（2026-09-22 更正：这里原文写的是"`Refresh` 全程 `healthy=false` → 每次刷新都有一个新连接不可用的小窗口"。那描述的是更早那版实现 —— 用一个可变的 `healthy` 标志表示"正在刷新"，现已改为从 epoch 自身派生准入判据。真正会产生不可用窗口的是**轮换连续失败、当前 epoch 越过自己的截止时刻**，其大小由 §10 的两个截止时刻决定。）
2. **receipt signer 必须跟随轮换**：`cmd/tee/main.go:208` `signer := proof.NewSigner(epoch)` 用的是**启动时捕获**的 epoch 快照；而 receipt 的 `KeyID` 就是该 epoch 签名密钥的 SPKI 哈希（`proof/receipt.go:305`；`internal/mtls/mtls.go:111-115` 注明 RA-TLS 叶的 "SPKI is the receipt KeyID"）。→ 只加一个 Refresh ticker 而不换 signer，会出现"RA-TLS 已轮换、receipt 仍用旧 epoch 签"，校验方按连接 attested key 核对时会失败。实现时必须把 signer/service 做成跟随 `adapter.Snapshot()`。

---

## 6. 不改机器的即时缓解（本次可用）

- 只想让 Hive 立刻能用：**重启 TEE**（重新出证，拿到新的 3h 窗口）。
- 只想验证"到底是什么过期"：`openssl s_client -connect 10.0.1.63:18090 -showcerts` 抓证书，再看 `.2` 扩展里 NitroTPM 叶的 `notAfter`。本次即用此法确认。
- 关注点提示：Hub 上 Hive 现在是**手工 tmux 跑**（无 systemd unit），重启/升级都要手工——排障时别误判成"服务已停止"。

---

## 附：复现本次审计的命令

```bash
# 1) 活体抓 TEE 证书并解析 .2 扩展里的 NitroTPM 链
ssh -i ssh-key.pem ubuntu@52.215.235.214 \
  'openssl s_client -connect 10.0.1.63:18090 -cert /etc/tokhive/hive-client.pem \
   -key /etc/tokhive/hive-client-key.pem -showcerts </dev/null 2>/dev/null' > /tmp/teecert_raw.txt
# 再用 cbor2 解 .2 扩展 → nitrotpm → COSE_Sign1 → payload.certificate / cabundle

# 2) 全仓证书有效期一览
for f in $(find . -name '*.pem' -o -name '*.crt' | grep -v '\.git/'); do
  openssl x509 -in "$f" -noout -subject -dates 2>/dev/null && echo "  ^ $f"
done
```

---

## 附录 B：选项 (ii)"改用 attestation 验证"具体是什么意思

### B.1 现状：hub 是"钉某一张证书"
- `cmd/hub/main.go:110` `-mtls-ca mtls/tee-cert.pem`
- → `main.go:411-427` `buildTEEClientTLS()` → `internal/mtls/mtls.go:66-108` `ClientMTLSConfig()`
- 里面做的是：`InsecureSkipVerify: true`（不查主机名）+ `VerifyPeerCertificate` → `leaf.Verify(Roots = {tee-cert.pem 那一张}, KeyUsages=[ServerAuth])`。
- 语义 = **"对端必须出示这一张证书"**。因为 SNP 的 RA-TLS 叶是自签的（`subject=issuer=CN=tokenhive-tee`），pin 的"CA"其实就是那张叶自己。
- 所以：证书**过期**即失效（24h）；TEE **换密钥/换叶**即失效（更早）；每次出证后都得人工重抓 `tee-cert.pem` 并重启 hub。
- 注意：这条路径**完全不看证书里的证据** —— 它信任的是"部署时运维手工 pin 过这张证书"（TOFU）。

### B.2 (ii)：不钉证书，改验"证书里带的证据"
把 `VerifyPeerCertificate` 换成 `shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{...})`（`shared/ratls_verifier.go:162-179`，返回的正是 `tls.Config.VerifyPeerCertificate` 回调）。它做三件事：

1. **解析对端这一握手出示的证书**（`ratls_verifier.go:43-70`）：
   - `spkiDER = MarshalPKIXPublicKey(leaf.PublicKey)`
   - 从扩展 `.2`（+ `.3` Secure Boot 标记）取证据：`snpAttestationFromCert(leaf)`
   - → `validateSEVSNP(snp, spkiDER)`
2. **验证证据是真硬件签的、且镜像正是期望的那个**（`verifyCombinedSecureBoot` → `verifyCombined` → `verifyCombinedAWS`）：
   - NitroTPM COSE_Sign1 签名 → 链到内嵌 `aws.nitro-enclaves` 根（`shared/aws_nitro_root.pem`，2019→2049）
   - SEV-SNP report（AMD 链 + VCEK/ASK/ARK + TCB/策略）
   - **SPKI 绑定**：证据的 `report_data` / NitroTPM `user_data` 提交的是**这张证书 SPKI 的哈希**（`snp_combined_aws.go:70-82 awsCombinedV2ReportData(bound=spkiDER,…)`）。⇒ 一张合法证据**不能被挪用到另一把 TLS 密钥上**（防拼接/重放）。这就是"验证据 + SPKI 绑定"的含义。
   - 返回 `app = snp-app:<sha256(bundle)>`、`base = snp-base:<PCR11>`
3. **比对 pin**：`gotDigest == opts.ExpectedImageDigest`（即 `-expected-app`），可选 `ExpectedBaseDigest` 钉 PCR 11（`ratls_verifier.go:168-176`）。

Hive 早就是这么干的：`hive/internal/teeclient/deployment.go:82` `shared.VerifyRATLSPeer(RATLSVerifyOptions{ExpectedImageDigest: d.ExpectedApp, ExpectedBaseDigest: d.ExpectedBase})`，配 `InsecureSkipVerify: true` + 仍然出示自己的 client 证书。

### B.3 落到 hub 要改什么（只此一处）
只有 `buildTEEClientTLS()`（`cmd/hub/main.go:411-427`）需要把 CA pin 换成 attestation 校验：

```go
cfg := &tls.Config{
    InsecureSkipVerify: true,
    MinVersion:         tls.VersionTLS12,
    VerifyPeerCertificate: shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
        ExpectedImageDigest: expectedApp,  // 复用 hub 已有的 -expected-app
        ExpectedBaseDigest:  expectedBase, // 可选，新增 flag
    }),
    Certificates: []tls.Certificate{clientCert}, // hub 仍须出示自己的证书
}
```

- **复用现成旗标**：hub 已经有 `-expected-app`（`cmd/hub/main.go:103`，`snp-app:<sha256 hex>`），今天只用在 receipt 校验（`buildVerifier` → `attest.Verifier{ExpectedApp}`，`main.go:460`）；部署脚本 `crosshost.sh` 也已把它传给 hub。通道校验直接复用，不引入新概念。
- **不影响另一方向**：`ServerMTLSConfig`（`ClientAuth=RequireAndVerifyClientCert` + `ClientCAs`）**只用在 TEE 侧**（`cmd/tee/main.go:256`、`cmd/faketee/main.go:235`），即"TEE 验 hub"那半边（hub-cert 到 2031/2036，本就不紧张）。所以 (ii) **只改 hub 验 TEE 这半边**，mTLS 仍是双向的。
- 建议加一个开关（如 `-tee-verify=pin|attestation`）以保留回退路径。

> **已实现（2026-09-17）**：`-tee-verify=pin|attestation`（默认 `pin`）已落地，`-expected-base` 未加（与 receipt 校验器一致地只钉 app）。见 §7。

### B.4 收益 / 前提
| | 钉证书（现状） | attestation（ii） |
|---|---|---|
| TEE 换叶 / 轮换密钥 | **拒绝**（须重抓 + 重启 hub） | **自动接受**（镜像哈希不变即可） |
| 信任来源 | 部署时手工 pin（TOFU） | 每次握手重新验证硬件证据 + 镜像身份 |
| 仍受 AWS 3h/24h 约束吗 | 是（叶 24h） | **是**（`verifyNitroChain` 仍 `leaf.Verify`） |

---

## 7. 实施记录：方案 A + 选项 (ii)（branch `fix/tee-ratls-refresh-attestation-verify`）

已实现，**只改本地代码，未动 AWS 上的 TEE 与 hub**（未重新部署、未改 `crosshost.json` 状态）。

### 7.1 改了什么

| 文件 | 改动 |
|---|---|
| `tokenhive/cmd/tee/ratls_refresh.go`（新） | epoch 刷新循环：`epochRefresher` 接口、`epochAssembly`、`serviceRuntime`（可热替换的 `*tee.Service`）、`nextRefreshDelay`、`runEpochRefresh` |
| `tokenhive/cmd/tee/main.go` | `buildEpoch` 改为返回 assembly；handler 经 `svcRuntime.get()` 取当前 service；`-mtls` 之外新增：sevsnp 平台启动刷新 goroutine |
| `tokenhive/cmd/tee/epoch_sevsnp.go` | 把 `*sevsnp.Adapter` 作为 `Refresher` 一并返回（simulated 返回 nil） |
| `tokenhive/cmd/tee/epoch_default.go` | 同上，`Refresher` 恒为 nil（软件证据不过期） |
| `shared/router_runtime.go` | `RunRATLSRefresh` 的第一个参数由 `*RATLSManager` 放宽为 `RATLSRefresher` 接口（`Refresh(context.Context) error`），使 tokenhive 的 adapter 能复用同一条循环/节奏/失败策略；tee_k/tee_t 的调用点不变 |
| `tokenhive/cmd/hub/main.go` | 新增 `-tee-verify=pin\|attestation`（默认 `pin`）；attestation 分支用 `shared.VerifyRATLSPeer`（证据 + SPKI 绑定 + `-expected-app`），仍出示 hub client 证书；`validateApplicationPin` 抽成唯一一处 pin 形状校验（receipt 校验器与握手共用） |
| `tokenhive/cmd/tee/ratls_refresh_test.go`（新） | 节奏 + 轮换落地的测试 |
| `tokenhive/cmd/hub/main_test.go` | `-tee-verify` 两种模式的测试 |

### 7.2 节奏（`nextRefreshDelay`）

```text
delay = clamp( Until(SNPSigningDeadline(当前证据)), 上限 RATLSRefreshIntervalSNP=2h, 下限 minRefreshFloor )
SNPSigningDeadline = NitroTPM 叶 NotAfter − SNPSigningMargin(5min)
```

> 2026-09-22 变更（见 §10）：原式为 `Until(SNPAttestationExpiry)`，即 `NotAfter − SNPRefreshMargin(30min)`，
> 下限 `10min`；现在瞄准的是**签名**截止时刻，下限收到 `2min`。

- 3h 叶 → 首次 2h 后轮换（此时叶还剩 1h，AWS 尚未重签 ⇒ 同叶空转，不换 epoch），此后 55min 后再来一次，
  正好落在 AWS 的重签点之后 → **永不接近 3h 悬崖**。
- AWS 若缩短叶 TTL，节奏自动跟随（上限不再独裁）——这条正是"别再靠猜"的部分。
- `Snapshot()` 失败（adapter 已无可用 epoch）→ 退回 `minRefreshFloor` 重试，而不是等满 2h 上限。

### 7.3 三个不能漏的实现点（§5.5 列出的两个 + 一个新增）

1. **signer 跟随轮换**：`serviceRuntime.adopt` 用 `proof.NewSigner(新 epoch)` 重建 service 并原子替换；handler 每次请求经 `get()` 取当前实例，所以轮换不需要重启、也不需要断连。旧实例仍被在途请求持有（因此旧 epoch 的 receipt 依然自洽可验）。
2. **证据必须先落盘再换 signer**：`adopt` 的顺序是 `WriteTEEIdentity` → `RecordTEEEvidence` → 替换 service。生产用 hash-only receipt，`EvidenceHash` 只能靠 evidence store 反查（本地 + 供 Hub 拉取的 `/v1/evidence`）；先换 signer 就会出现"签得出、验不了"的窗口。落盘失败 ⇒ 整个轮换放弃，旧 service 继续签（有测试覆盖）。
3. **inbox 密钥完全不碰**：仍由 `cmd/tee/main.go` 启动时 `GenerateInboxKey()` 生成一次、不落盘，不进 `serviceRuntime.template` 之外的任何轮换路径 → **provider 的密文 envelope 无需重新加密**（§5.5 结论在实现后依然成立）。
4. **`AttestationHealth` 传 nil**：那条自愈路径会重启客户机，tokenhive 的 TEE 进程没有对应的恢复动作，故不加；刷新失败只记录日志（同时表现为 Hub 侧 TLS 对端消失）。这是**已知取舍**，见 7.6。

### 7.4 验证到什么程度

| 验证 | 结果 |
|---|---|
| `go build ./...`、`go build -tags sevsnp ./...` | 通过（`demo_lib` 的 cgo 链接失败是缺 `bin/libreclaim` 的既有环境问题，与本次无关） |
| `go vet ./shared/... ./tokenhive/...` | 干净 |
| `go test ./shared/... ./tokenhive/...` | 全绿 |
| `ratls_refresh_test.go`：合成 AWS-tagged 证据（含自造的 NitroTPM 叶 `NotAfter`）驱动节奏 | 长寿命叶→2h 上限；1h 叶→~30min（证明节奏真的跟随 AWS，而不是固定上限）；已过期叶→10min 下限；`Snapshot` 失败→10min |
| `ratls_refresh_test.go`：一次真实循环迭代（预取消 ctx） | 轮换后 service 实例被替换、`tee_identity.json` 指向新 key、证据进 store；证据不可发布时**拒绝轮换**且旧 service 继续签 |
| `main_test.go`：`-tee-verify` 两模式 | pin 模式无 CA ⇒ 返回 nil（明文通道）；pin 模式仍能对钉住的 CA 做链校验；**attestation 模式对"无 attestation 扩展的合法证书"必须拒绝**（fail-closed，而不是退化成只跳主机名校验）；`-mtls-ca` 与 attestation 同时给 ⇒ 报错；缺/坏 `-expected-app` ⇒ 报错 |
| `tokenhive/harness/harness.sh` | ✅ 0 FAIL（场景 1–18）。第一次运行出现过 4 处 FAIL，**全部**是本机删除护栏导致 `.sim` 清理失效，与本次改动无关；已用四组对照实验确认，见 7.5 |

### 7.5 第一次 harness 运行那 4 处 FAIL 的归因（已实验确认）

本机存在"**单轮**删除超过 50 个非 `/tmp` 路径即静默拒绝"的护栏（`[safe-delete][SAFE_DELETE_BULK_CONFIRM_REQUIRED]`，scope=turn）。`.sim` 里积压了前两天的大量 receipt 时，harness 开头的 `wipe "$SIM"` 会把这一轮的删除额度耗尽：

- `!! FAIL: expected 2 receipts under cheap-sim, got 4`、`!! FAIL: expected 1 receipt, got 4` —— 后续场景的 `wipe` 变成空操作，计数断言量到的是上一场景残留（脚本自己的注释就说："a refused wipe is not a harmless no-op — it turns a real assertion into a measurement of the previous scenario"）。
- `!! FAIL: mTLS request did not complete` + `tee mtls: tls: private key does not match public key` —— 部分删除后 `.sim/hub-client.pem` 是 09-17 的旧证书，而 `hub-ca.pem`/`hub-client-key.pem` 被 `EnsureMTLSCerts` 重新生成（`writePEMIfAbsent` 逐文件判断，于是产生"新 CA + 新私钥 + 旧证书"的错配三元组）；`tls.LoadX509KeyPair` 在 hub 读**自己**的证书时失败，与本次改动的验证模式无关。

四组对照（`FAIL` 计数）：

| 运行位置 | base `507170c` | new `4c4347d` |
|---|---|---|
| 主仓库（删除护栏生效、`.sim` 有积压） | 0（积压已被前次运行部分清掉） | **0** |
| `/tmp` git worktree（删除不受护栏影响，`.sim` 全新） | 0 | **0** |

结论：harness 场景 1–18 在本次改动前后都是 0 FAIL；上面 4 处 FAIL 只出现在"删除额度耗尽"的那一次运行里。

> 顺带发现（与本次无关，**已单独修复，见 §8**）：`EnsureMTLSCerts` 用 `writePEMIfAbsent` 逐文件判断，只要 `hub-ca.pem` / `hub-client.pem` / `hub-client-key.pem` 三件套中有任一缺失，就会只补缺失的那几个，产出互不匹配的一套。应改为"三件套要么全部复用、要么全部重生成"。

### 7.6 未做 / 后续

> **后续已落地（2026-09-17）：四个调用点全部切换完毕，见 §9。** 下面保留当时的判断，作为切换前的记录。

- **未切换任何部署调用点**（按"先不要动 AWS"的指示）。切到 attestation 只需改旗标，四个调用点的处置：

  | 位置 | 现状 | 建议 |
  |---|---|---|
  | `tokenhive/cloudtest/snp/crosshost.sh:383`（跨机 AWS，现行主路径） | `-mtls-ca mtls/tee-cert.pem` | 换成 `-tee-verify attestation`（同行组里已有 `-allowed-platforms aws-sev-snp -expected-app 'snp-app:${app_hash}'`，无需另加；`-mtls-cert/-mtls-key` 保留） |
  | `tokenhive/cmd/single/main.go:219`（单机密实例） | `-mtls-ca, teeCert` | 换成 `"-tee-verify", "attestation"`。但这样 `fetchTEECert()`/`teeCert` 与 tee 的 `-init-addr` 自举就失去消费者，属于一次额外的清理，建议单独一步做 |
  | `tokenhive/cloudtest/remote/run-all.sh:76`（同一脚本跑 simulated 与 sevsnp） | 恒 `-mtls-ca` | 需按 `TEE_PLATFORM` 分支：sevsnp ⇒ `-tee-verify attestation`，simulated ⇒ 保持 pin（sim 证书没有 attestation 扩展，attestation 模式必然拒绝） |
  | `tokenhive/harness/harness.sh:804/814` | `-mtls-ca` | **保持 pin**：faketee 是 simulated |

- 切到 attestation 后，`fetch`（TOFU `/v1/init-cert`）与 `tee-cert.pem` 的分发不再是信任链的一部分，可作为后续简化（也可留作人工核对）。
- `docs/TokenHive 真实 TEE 部署与测试手册（AWS SEV-SNP）.md` §393/§406/§426 把 TOFU→`-mtls-ca` 写成信任建立主路径，切换后需同步改写。
- 刷新失败的重试只有 10min 下限；若 `Refresh` 连续失败（如 `/dev/sev-guest` 卡死导致 `healthy` 永久为 false），进程没有自愈手段（见 7.3-4）。要么在部署层加重启策略，要么后续接 `AttestationHealth`。

⇒ **(ii) 不是方案 A 的替代品，而是它的配套**：A 负责让证据保持新鲜（解决 3h/24h），(ii) 负责让 hub 不再需要重新钉证书（解决换叶即失效）。

---

## 8. 实施记录（三）：证书有效期与三件套一致性（2026-09-17）

> 仍然**只改本地代码**，没有动 AWS 上的 TEE 与 hub（没有重新部署、没有重新生成 `.certs`）。
> 分支 `fix/tee-ratls-refresh-attestation-verify`，已 force-push 到 fork（`2245fee → df0c1a1`，因为把本文撤出提交必然重写该提交）。

### 8.1 先回答"实例中间 CA 和 RA-TLS 叶"里哪些是我们的

| 证书 | 归属 | 能不能改 |
|---|---|---|
| Nitro **实例中间 CA**（24h） | **AWS NSM 签发**，在 NitroTPM document 的 `cabundle` 里 | **改不了。** 它的 `NotAfter` 是 AWS 给的，我们只能"在它到期前重新出证整份 document"（= §5 方案 A，已实现） |
| **RA-TLS 叶**（24h） | **自己签**（`shared/ratls_manager.go` `Refresh()`） | **已改**：24h → **5y** |
| 仿真 mTLS fixtures（24h） | **自己签**（`mtls.GenHubClientCerts` / `GenMockProviderCerts` / `shared.GenCerts`） | **已改**：CA 10y / 叶 5y |

所以"两个 24h"里只有 RA-TLS 叶和 fixtures 是我们的；实例中间 CA 那张属于 §4.5-B 的结论 —— 对它的正确动作是**重新出证**，不是改有效期。

### 8.2 为什么 24h 窗口该去掉

RA-TLS 的**新鲜度**由证据负责（AWS 侧 hours 级）与刷新节奏负责，X.509 窗口从来不是新鲜度机制：

- 做 attestation 校验的一方（`VerifyRATLSPeer`）根本不读它 —— 它读的是证书里的证据。
- 读它的一方（hub 的 cert pin、标准 TLS 客户端、跨多天的 cloudtest fixtures）则**只**受它约束。

于是 24h 的实际效果是：**一个没跑（或跑不起来）刷新的部署，会在启动后正好一天停止认证**，而这个信号与"证据是否新鲜"无关，只会误导排障（§4.5-A 的"连带风险"就是这么来的）。fixtures 同理：一次跨天的实验不该被证书窗口打断。

### 8.3 改了什么（3 个提交）

| commit | 内容 |
|---|---|
| `0994c8f` | （amend 自 `2245fee`）方案 A + 选项 (ii)。本文撤出提交、文件保留在工作区（untracked）；提交信息里对本文的引用改成自述，避免指向一棵不含它的树 |
| `eb8a029` | 证书有效期：`shared/ratls_manager.go` 自签 RA-TLS 叶 24h → 5y；`tokenhive/internal/mtls/mtls.go` 新增 `FixtureCACertLifetime=10y` / `FixtureLeafCertLifetime=5y` 并用于两组 fixtures；`shared.GenCerts()` 复用同一对常量 |
| `df0c1a1` | `EnsureMTLSCerts` 改成"三件套要么全部复用、要么全部重生成"，并删掉已无调用者的 `writePEMIfAbsent` |

CA 比它签的叶活得久，是为了"重签叶不动已 pin 该 CA 的部署"；这也是磁盘上 `.certs`（`hub-ca` 2036 / `hub-cert` 2031）一直在用的划分 —— 这次是把代码对齐到它。

### 8.4 验证

| 验证 | 结果 |
|---|---|
| `go build ./tokenhive/... ./shared/...`（含 `-tags sevsnp`） | 通过 |
| `go vet ./shared/... ./tokenhive/...` | 干净 |
| `go test ./shared/... ./tokenhive/...` | 全绿 |
| `go run ./tokenhive/cloudtest/snp/gencerts <tmp>` + `openssl x509` | `hub-ca`/`mp-ca` → **2036-09**（10y）、`hub-cert`/`mp-cert` → **2031-09**（5y），与磁盘 `.certs` 一致 |
| harness 环境里的 `.sim/hub-ca.pem` / `hub-client.pem` | 2036 / 2031 —— `EnsureMTLSCerts` 路径也确认了 |
| `TestEnsureMTLSCertsWritesTheIdentityAsASet` | 新测试；**在旧实现上会失败**（`the stale certificate was kept beside a freshly generated CA`），新实现通过 —— 已用 `git stash` 实测旧实现确认非空转 |
| `TestFixtureCertsAreLongLivedAndChain` / `TestRATLSLeafWindowIsLongLived` | 新测试：fixtures "多年 + 真的链到旁边的 CA"、RA-TLS 叶窗口 > 1 年 |
| `bash tokenhive/harness/harness.sh`（`/tmp` git worktree @ `df0c1a1`） | **0 FAIL**（场景 1–18） |

### 8.5 你之前要我定的"两件后续"：一件纯部署，一件是代码 bug（已修）

1. **切换四个部署调用点 —— 主要是部署/脚本，不是代码逻辑**
   - `crosshost.sh:383`：只是把 `-mtls-ca mtls/tee-cert.pem` 换成 `-tee-verify attestation`（同行组里已有 `-expected-app`）。
   - `cloudtest/remote/run-all.sh:76`：需要按 `TEE_PLATFORM` 分支——sevsnp 用 attestation，simulated 保持 pin（sim 证书没有 attestation 扩展，attestation 模式必然拒绝）。
   - `harness.sh:804/814`：**保持 pin**（faketee 是 simulated），不动。
   - `cmd/single/main.go:219`：改旗标后 `fetchTEECert()` / tee 的 `-init-addr` 自举失去消费者，是**可选清理**，建议单独一步。
   - ⇒ 结论：**没有"必须改代码"的部分**；这一步是 rollout 时的配置动作。
2. **`EnsureMTLSCerts` 三件套错配 —— 是代码 bug，值得修**（症状是延迟且远离根因的 `tls: private key does not match public key`），已在 `df0c1a1` 修掉并配了会失败的回归测试。

### 8.6 仍未做

- **没有重新部署**：AWS 上那台 TEE 仍在服务部署时签出的 24h 叶（换叶要靠重新部署 + §8.3 的刷新循环）。所以 §3.1/§3.2 的**实测值依然是那台机器的现状**，§8 说的是"代码从此以后会签什么"。
- **没有重新生成 `.certs/`**（本就是 10y/5y），`ensure_certs()` 的"见到 `hub-ca.pem` 就复用"也没变 —— 现有 AMI 不受影响。这次改的是"将来万一需要重生成"时的行为。

---

## 9. 实施记录（四）：把 §7 之外新发现的问题全部修掉（2026-09-17）

> 仍然**只改本地代码与脚本**：没有在 AWS 上重新部署、没有动正在运行的 TEE / hub，也没有重新构建镜像。
> 分支 `fix/tee-ratls-refresh-attestation-verify`，四个提交（`604911f` → `a2433e2` → `7559e53` → `d5aa723`）。

这一轮先做了一次复查（"有没有逻辑漏洞 / 能不能再简化 / 部署后证书有效期够不够"），把发现的东西记在 §9.1，然后按"全都修"逐条落地。

### 9.1 处置清单

| # | 严重度 | 问题 | 处置 |
|---|---|---|---|
| ① | **部署阻塞** | hub 默认 `-tee-verify=pin` 与 TEE 的**无条件轮换**互斥：pin 模式在启动时读一次 `mtls/tee-cert.pem`，而 sevsnp 的实例每个 epoch（≤2h）重签一次叶，于是首个刷新周期后握手必然失败 | 三个真实部署调用点全部切到 `-tee-verify attestation`（§9.2） |
| ② | 中 | TOFU 的两条导出路径都是**启动快照**：`/v1/init-cert` 缓存启动时的 `tls.Config`；`WriteTEECert` 只在启动时写一次 | 两条都改为跟随轮换（§9.3） |
| ③ | 中 | **发布失败不缩短重试**：`Refresh` 已经成功、但 epoch 没落到 service 时，节奏仍按证据的新鲜度退到 2h 上限 | `nextRefreshDelay` 增加 `published` 形参，未落地即返回 `minRefreshFloor` |
| ④ | 低 | `EnsureMTLSCerts` 只判断"三个文件都在"，**看不出错配**（丢了其中一个文件的目录、或两个进程竞争创建的目录会带着一套从未属于彼此的证书通过检查） | 改为"整套是否还能用"：CA 能解析、私钥属于证书、证书是 CA 签的 client 证书；否则整套重建，并写回后复核（§9.4） |
| ⑤ | — | ~~`crosshost.sh` 给 agent 传的 `-ca "$SIM/ca.pem"` 在部署链里无人创建，起不来~~ | **误报，已撤回**：`mockprovider` 即使收到显式 `-ca/-cert/-key`，也会把 CA 复写到 `shared.CAPEMPath()`（`tokenhive/cmd/mockprovider/main.go:216`），该文件必然存在 |
| ⑥ | 低 | 刷新 goroutine 用 `context.Background()`，不可取消 | **不改代码，判定为设计取舍并写明理由**（§9.5） |
| 简化 | — | `serviceRuntime.includeEvidence` 与 `template.Signer.IncludeEvidence` 是同一事实的副本 | 删掉字段，`adopt` 直接从 template 读 |
| 简化 | — | hub 身份路径在 `hubClientIdentity` 与 `EnsureMTLSCerts` 里各写了一遍 | 新增 `shared.HubIdentityPaths()` 作为唯一出处 |

### 9.2 ① 部署调用点：改了什么

| 位置 | 改前 | 改后 |
|---|---|---|
| `tokenhive/cloudtest/snp/crosshost.sh`（跨机 AWS，主路径） | `-mtls-ca mtls/tee-cert.pem`，并把 `.certs/tee-cert.pem` 推到主机 | `-tee-verify attestation`（同行已有 `-allowed-platforms aws-sev-snp -expected-app 'snp-app:${app_hash}'`、`-mtls-cert/-mtls-key` 保留）；**不再分发 `tee-cert.pem`** |
| `tokenhive/cloudtest/remote/run-all.sh` | 恒 `-mtls-ca "$SIM/tee-cert.pem"` | 按 `TEE_PLATFORM` 分支：sevsnp ⇒ `-tee-verify attestation`；simulated ⇒ 保持 pin（sim 叶没有 attestation 扩展，attestation 模式必然拒绝） |
| `tokenhive/cmd/single/main.go`（单机密实例） | `-mtls-ca teeCert`，且 supervisor 先经 `/v1/init-cert` 把叶拉回本地再交给 hub 固定 | `-tee-verify attestation`；删掉 `fetchTEECert()`，改为等 tee 自己写出的 `tee-cert.pem`（§9.3 末） |
| `tokenhive/harness/harness.sh:804/814` | `-mtls-ca` | **不动**：faketee 是 simulated，epoch 固定，pin 就是完整信任声明 |

`crosshost.sh fetch` 保留，但语义从"建立信任"变成"人工核对"：hub 不再固定它取回的证书，端点返回什么都不会改变 hub 的判定。`TEE_INIT_ADDR`/`TEE_INIT_TOKEN` 因此从信任链降级为无 sshd 实例上的只读窗口。

### 9.3 ② 的两条路径都改为跟随轮换

轮换会同时换掉监听器的密钥、receipt signer 与证据，但"给外部看的东西"当时漏了两处：

1. **`/v1/init-cert`**：`serveInitCert` 捕获的是启动时的 `*tls.Config`，返回的是启动叶。改为每个请求现取 `leafCertPEM(mTLSConfig)`——这个端点的契约就是"监听器**现在**所持的那张叶"，而它恰好是唯一一个目的就是学习当前叶的调用方。
2. **`tee-cert.pem`**：只在启动时写一次，之后永远描述一张没人再服务的证书。改为在 `publishEpoch` 里，紧跟证据落盘之后、`adopt` 之前重写；来源是 `epochRefresher.ServerTLSConfig()`（= hub 侧同一个 accessor，sevsnp adapter 的 `GetCertificate` 读的是 `a.current`，而 `Refresh` 在返回前已发布新 epoch，所以拿到的就是轮换后的叶）。取不到 server TLS config 时**拒绝整次轮换**，与其它半失败一致：宁可继续用上一套自洽状态（文件仍准确描述它），也不留一个"监听器与实际发布物互相否认"的窗口。

`cmd/single` 的自举因此完全失去消费者：它拉回来的字节，tee 子进程本来就已经写在了同一个路径（`ConfigDir() == TOKENHIVE_SIM_DIR`）。改为 `waitForTEECert()` 只等这个文件出现——保留原本由自举顺带提供的**启动顺序**（不要在 tee 能服务之前让 hub 去拨），去掉那次多余的 HTTP 往返与令牌依赖。tee 的 `-init-addr`/`-init-token` 仍原样传给子进程（与双机形态保持一致的 flag 面，且 loader 本就会注入这两个 env）。

### 9.4 ④ 与两处简化

`EnsureMTLSCerts` 由"三个文件是否都在"改为"这套是否还能一起用"：走 `loadHubMTLSIdentity(ca, cert, key)`，要求 CA 可解析、`tls.LoadX509KeyPair` 能配出一对、且叶是**由该 CA 签发的 client 证书**；不满足就整套重建，**写完再读回复核一遍**，让"目录写不进去 / 有并发写者"在启动时以启动失败暴露，而不是以后变成一次没有可见原因的握手失败。回归测试 `TestEnsureMTLSCertsRebuildsAMismatchedSet` 放一份 staleCA + freshCert + freshKey，断言整套被重建、旧 CA 不被复用。

同时把 hub 侧解析同一批默认路径的逻辑收敛到 `shared.HubIdentityPaths()`：路径只有一处拼写，避免"写在一个地方、读在另一个地方"。hub 在操作者显式给了 cert+key 时也不再多余地跑一次 `EnsureMTLSCerts`。

### 9.5 ⑥ 为什么不去改成可取消的 context

结论是**不改**，理由是取消这件事在这里只有坏处和风险，没有好处：

- 刷新循环应当**恰好与监听器同寿**。`RunRATLSRefresh` 在 ctx 被取消时的行为是"再 adopt 一次当前快照然后返回"——于是循环停了、epoch 不再更新，而监听器继续用那份正在老化的证据应答，这是比不取消更糟的状态。
- 两条服务路径的结尾都是 `log.Fatal(...)`，**不会**沿 defer 栈退回：任何 `defer cancel()` / `defer stop()` 都执行不到，接一个可取消 ctx 在今天的结构里是纯装饰。
- 用 `signal.NotifyContext` 让它"响应 SIGTERM"会**改掉默认语义**：注册信号处理会屏蔽默认的"收到信号即终止"，除非同时实现一套 graceful shutdown；一个部署脚本按 SIGTERM 停不下来的 enclave 是实实在在的部署隐患。

所以代码里保留了 `context.Background()` 并把这三点写进了注释（`cmd/tee/main.go`）。如果将来真的引入优雅关停（比如接 `AttestationHealth` 一起做），届时再把 ctx 挂到那条关停路径上，才是对的做法。

### 9.6 验证

| 验证 | 结果 |
|---|---|
| `gofmt -l tokenhive/cmd/` | 干净（本次触及的文件均不在列表内） |
| `go build ./tokenhive/...` / `go build -tags sevsnp ./tokenhive/...` | 均通过 |
| `go vet ./tokenhive/...` | 干净 |
| `go test ./tokenhive/...` | 全绿（含 `cmd/tee`、`cmd/hub`、`cmd/internal/shared`、`internal/mtls`） |
| 新增 `TestRunEpochRefreshAdoptsAndPublishesRotatedEpoch` 的叶断言 | 通过；**在临时移除发布逻辑的实现上会失败**（实测 `read published RA-TLS leaf: ... no such file or directory`），非空转 |
| 新增 `TestRunEpochRefreshRefusesARotationItCannotPublishATleafFor` | 通过；同一实验下失败（`runtime adopted an epoch whose RA-TLS leaf could not be published`） |
| `TestEnsureMTLSCertsRebuildsAMismatchedSet` | 通过（`staleCA + freshCert + freshKey` 被整体重建） |
| `bash tokenhive/harness/harness.sh`（`/tmp` git worktree @ `d5aa723`，场景 1–18） | **0 FAIL**，exit 0（45 项 OK 断言；在 `/tmp` 跑以绕开本机删除护栏导致的 `.sim` 清理失效，见 §7.5） |
| `grep -c FAIL` on 完整 harness 输出 | 0 |

### 9.7 仍未做

- **没有重新部署，也没动 AWS 上那台 TEE / hub**：`crosshost.sh` 与 `cmd/single` 的改动是"下次部署会怎么跑"。现有实例仍在用 pin 语义的旧 hub 参数，若要保持在线超过一个刷新周期，需要按新脚本重新 `deploy`（或手工把 hub 换成 `-tee-verify attestation` 并去掉 `-mtls-ca`）。
- **没有重新构建 AMI**：AMI 里的 bundle 未变，本次改动只影响主机侧脚本与单机 supervisor 的行为；单机 AMI 若要生效需重建。
- **pin 模式保留**：它没有被删掉，但只对"epoch 不变"的平台成立（simulated / harness）。真机上一旦用 pin，就回到了 §7 的 2h 失效问题。
- **刷新彻底失败仍无自愈**：若 `Refresh` 连续失败（例如 `/dev/sev-guest` 卡死使 `healthy` 永久为 false），进程只会持续以 `minRefreshFloor` 重试并记录日志，没有重启手段（见 §7.6 末与 §9.5）。

---

## 10. 实施记录（五）：每 2h50m 一次的 RA-TLS 准入黑窗（2026-09-22）

> 分支 `fix/tee-diagnostics`（基于 `tokhive`），三个提交。**只改 TEE 侧判据与节奏**，不改线协议、不改 Hub。

### 10.1 问题

§7 接上刷新循环之后，TEE 不再出现 §4 那种"启动 3 小时后彻底失效"，但出现了一种**周期性**的整机不可握手：

- Hub 每 10 分钟告警一次 `WARN TEE inbox key unavailable; Hive will keep asking  error="Get \"https://<tee>:18090/v1/credential-key\": remote error: tls: internal error"`。
- TEE 串口控制台同一节奏地记 `TEE listener not ready; refusing new handshakes`，每条间隔 10 分钟。
- 每次持续约 20 分钟，然后自己恢复。作者第一次遇到时以为与"刚重启 Hub"有关（重启时刻恰好落在窗口内），实际无关。

`tls: internal error` 是 Go 把 `GetCertificate` 返回的错误转成的 **alert 80** —— 也就是说握手在 TEE 这一侧就被**主动拒绝**了，根本没走到 Hub 的证书校验（Hub 侧 `mtls.ClientMTLSConfig` 走标准 `leaf.Verify`，对这张叶没有额外 margin，叶有效它就接受）。所以现象里的 `internal error` 不是"证书不能验"，而是"TEE 不肯出示"。

### 10.2 排查方式

TEE 实例没有 sshd，现场通道只有两条，这次两条都用上了：

1. **串口控制台**：`aws ec2 get-console-output --instance-id … --latest`。注意 **`Latest=True` 不能省** —— 默认返回的是一份延迟的旧快照，会让人误以为"启动后就再没输出过"（本次就先把判断带偏了一次）。
   拿到后按 JSON 逐行解析（`level`/`msg`/`time`），把 25 小时里的 150 条记录排成时间线：**周期恒定 2h50m12s**，误差 ±1 秒，没有任何例外 —— 这就排除了"偶发失败"。
2. **从 Hub 主机抓 TEE 的 RA-TLS 叶**（Hub 持 `hive-client.pem`）：
   ```bash
   echo | openssl s_client -connect <tee>:18090 \
       -cert /etc/tokhive/hive-client.pem -key /etc/tokhive/hive-client-key.pem \
       -CAfile /etc/tokhive/hub-ca.pem -showcerts 2>/dev/null \
     | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > leaf.pem
   ```
   交给 `tokenhive/cloudtest/probe_ratls` 读出叶里 NitroTPM 证据的 `notBefore`/`notAfter`。
   实测：**叶子寿命正好 3h**，且 `notBefore` 恰好等于上一次轮换成功的时刻 —— 说明 AWS 是**按需**签发的，
   只是在到期前约 **9m48s** 才肯换新（两次重签间隔恒为 2h50m13s）。
3. **对照代码**：TEE 侧准入判据（`sevsnp.Adapter` 的 epoch 截止时刻）与 Hub 侧的校验（`internal/mtls`）逐行对照，
   确认两侧对"这张叶还能不能用"的答案不一致，且差异正好是配置里的那个 margin。

### 10.3 根因

一个 margin 同时承担了两件事，而其中一件是错的：

```text
旧: admission deadline = NitroTPM 叶 NotAfter − SNPRefreshMargin(30m)
    Hub 接受这张叶到           NotAfter（不含 margin）
    AWS 重新签发这张叶于       NotAfter − 9m48s

⇒ 黑窗 = margin − 重签提前量 = 30m − 9m48s = 20m12s
```

黑窗内**重试是无效的**：`Refresh` 每次都成功，但 AWS 还没到重签点，拿回来的是**同一片叶**；新 epoch 的截止时刻由那片叶自己的 `NotAfter` 决定，与何时轮换无关，于是新 epoch 一建出来就已经过了 margin，`GetCertificate` 继续拒绝。叠加当时的重试下限 `10m`（比 9m48s 的重签窗口还宽），重试网格可以整窗跨过重签点 —— 本次恢复纯属运气：那一次重试落在重签点前 5 秒，TPM 调用本身跨过了它。

### 10.4 修复（3 个提交）

| commit | 内容 |
|---|---|
| `a126328` | **拆开两个截止时刻**。`SNPAdmissionDeadline = 叶 NotAfter`（与验证方逐字一致）、`SNPSigningDeadline = NotAfter − SNPSigningMargin(5m)`。准入用前者，出收据用后者，轮换节奏瞄准后者。 |
| `205ca4a` | **刷新不得倒退**。新 epoch 只有把准入截止推得更远才替换当前 epoch；同叶/更旧叶的轮换是 no-op（不写 identity/evidence、不重建 service、不 retire 活连接），同时保留"发布失败可重试"。 |
| `9380da0` | **重试下限 10m → 2m**。2m 窄于 9m48s 的重签窗口，重试网格不可能整窗跨过。 |

三者合力后的稳态：`T+2h` 那次是**同叶空转**（无错误日志、无连接 churn），`T+2h55m`（签名截止 = 重签点
`+4m48s`）**第一次排定尝试就命中新叶**。黑窗消失。

### 10.5 影响

**功能**

- 周期性整机不可握手（每 3 小时约 20 分钟）消失。
- 最坏情况从"**任何**握手都被拒 20 分钟"退化为"握手照常、**收据停发**不超过 5 分钟"：只有
  `[NotAfter−5m, NotAfter]` 这 5 分钟内，TEE 会以 `ErrAttestationStale` 拒绝新任务（不分配序号、不花 provider 额度）。
- 轮换不再因"证据没变"而 retire 所有活连接 —— 之前每次空转轮换都会打断在途连接做无用功。

**信任语义（需要知情的取舍）**

- 一张**新签发**收据的最小可验证余量由 30 分钟降到 **5 分钟**：`SNPSigningMargin` 是"签出时距叶到期至少还剩多久"的
  承诺，它现在更小。代价是收据在极端情况下（签发后 5 分钟内叶到期）可验证窗口更短；收益是准入判据与验证方
  完全对齐，不再有"验证方接受、TEE 自己拒绝"的错位。这属于信任策略选择，改动处已在代码注释里写明理由。

**兼容性**

- 无线格式变更，Hub 侧无需改动（Hub 从未使用过这个 margin）。
- `tee_k` / `tee_t` 仅跟随函数改名：它们的 `attestationExpiry` 一直是"缓存重新出证期限"，现在等于
  `NotAfter − 5m`（原来 `−30m`）⇒ 缓存命中时间变长、按请求重新出证的窗口变小，行为不变。
- 本仓库其余引用点（`probe_ratls`、部署手册）已同步。

**验证**

- 新增/反转的测试：10 分钟到期的叶**应当被准入**（旧断言是"必须拒绝"，已按新语义反转）；叶真过期才 fail-closed；
  签名边界用 6m / 4m 夹住 5m；同叶与更旧叶不替换、更远叶替换；空转 tick 断言**没有** retire 连接。
- `go build ./...` + `go vet` + `go test ./shared/... ./tee_k/... ./tee_t/... ./tokenhive/...` 全绿，
  且**逐个提交**单独验证过（每个提交自身可编译、测试通过）。
- `bash tokenhive/harness/harness.sh` 在 `/tmp` 的干净 worktree 里 A/B（基线 `tokhive` vs 本分支尖）：
  **18 场景 / 45 OK / 0 FAIL，断言逐行相同**。

## 11. 实施记录（六）：证书轮换的影响面 —— 买家与卖家分别会看到什么（2026-09-22）

> 本节只做**核对与记录**，不改代码。判据全部来自本分支尖的源码（位置随行标注）。生产 Hub 跑在独立仓库
> `tokhive-mvp`，其 `Verify` 实现不在本仓库，凡依赖它的结论都已单独标注。

### 11.1 轮换换什么、不换什么

轮换要解决的是"证据会过期"，所以它只动**与证据绑死的那两样**：

| 身份 | 轮换时 | 代码位置 |
|---|---|---|
| TEE 服务端 RA-TLS 叶（Hub→TEE 握手用） | **换** | `tokenhive/platform/sevsnp/adapter.go`（`Refresh` 换 epoch） |
| receipt 签名 key（`KeyID`） | **换** | `tokenhive/cmd/tee/ratls_refresh.go`（`adopt`） |
| credential inbox key | **不换**：进程启动生成一次，注释写明 deliberately untouched | `ratls_refresh.go:189-192`、`tokenhive/cmd/tee/main.go`（`GenerateInboxKey`） |
| relay 通道（TEE 拨 Hub 去接 provider） | **不换**：WebSocket + `RelayKeyHeader` 共享密钥，不用客户端证书 | `tokenhive/cmd/tee/main.go:87-92`、`relayHeaders()` |
| Hub 侧信任根 | **不换**：AWS NitroTPM root 在 measured bundle 里 | `tokenhive/internal/mtls`（`LoadCAPath`） |

结论：**凭据平面（卖家的一切）与证书轮换完全解耦**；唯一会让 provider 重新注册 token 的是 **TEE 进程重启**
（inbox key 换），不是轮换。

### 11.2 AWS 正常时

**卖家：无影响。** 卖家的在线通道是 agent ↔ Hub（Hub 自己的 WS），不经 TEE TLS；与 TEE 的唯一接触是
注册/续期时经 Hub 取 inbox key（`CredentialKey` → `/v1/credential-key`，Hub→TEE mTLS）。inbox key 不变，
已经封给它的 envelope 继续可用（`tokenhive/hub/tee.go` 的 `CredentialKey` 每次现取、不缓存，正是为了不吃旧 key）。

**买家：三条窗口，前两条无感，第三条才是"毫秒级"的那一个。**

1. **空闲连接被退役**：`rotate()` 只 close `idle` 连接（`rotated_connections.go:140-157`），在途连接留给
   `track`（`:102-130`）在它落回 idle 时关。Hub 侧连接池是 `&http.Transport{}`（`cmd/hub/main.go:139`），
   下次请求重新握手拿新叶即可 —— Hub 对叶的判据是标准 `leaf.Verify`，对轮换后的新叶没有额外 margin，
   所以这一步无感。
2. **在途请求 / 流式会话不被打断**：`Service.perform` 把本次交换的 signer **pin 住**（`tee/service.go:464-473`），
   收据与它所在连接的叶同属一个 epoch；WebSocket session 的连接是 `hijacked`，`track` 明确不 close 它，
   会话跨轮换继续跑。注意一个语义点：**session 的 terminal receipt 故意用轮换后的新 key 签**
   （`tee/service.go:876-884`），所以"收据 KeyID 与其所在连接的叶"在长会话里可以不一致。本仓库 Hub 不把
   两者交叉校验（`Verify` 是注入的 verifier，只验链 + app + policy；`hub/hub.go:513`），但若将来有验证者
   做这种绑定，需要知道这是有意的。
3. **复用竞态（唯一可能被买家看见的失败）**：Hub 恰好在 TEE close 的空隙里复用了那条连接 → `guard`
   回 `503 connection belongs to a retired attestation epoch; reconnect`（`rotated_connections.go:76-89`）。
   Hub 侧没有针对 503 的重试，只有 `executeForProviders` 的候选循环（`hub/schedule.go:362-390`），
   而**所有候选共用同一个 TEE** —— 它靠重连建立新连接来成功；若此时已 relay 过字节或 start 帧，则不 fallback，
   买家直接看到一次失败。窗口是毫秒级、每个真轮换一次。

另外，只有**真轮换**才有连接 churn：每 2h 的空转 tick（同叶）被 `publishEpoch` 的 `serving()` 早返回
（`ratls_refresh.go:236-243`）与 adapter 的 `supersedes`（`adapter.go:247-249`）双重挡掉，不建文件、不 retire 连接。

### 11.3 AWS 不正常时（三档）

| 档 | 触发 | 买家 | 卖家 |
|---|---|---|---|
| A | `Refresh` 失败，但叶未到期 | **无感**：准入跑到叶自己的 `NotAfter`（`adapter.go:240`），只是节奏延后 | 无感 |
| B | 进入 `[NotAfter−5m, NotAfter]` 仍拿不到新叶 | 所有 `Execute`/`OpenSession` 被 `ErrAttestationStale` 拒（`service.go:317`、`:679`），**先于**分配 `ProviderSeq` ⇒ 不缺号、不花费额度；上限 5 分钟 | 无感（inbox key 没变） |
| C | 叶到期后 AWS 仍不恢复 | **握手全拒**：`GetCertificate` 返 `ErrNotReady`（`adapter.go:147-151`）→ alert 80 → Hub 侧读到 `tls: internal error`；已建立的长连接也救不了（`guard` 放行，但 service 仍拒） | 新 agent 注册失败；在线 agent 的隧道还在但没有任务可跑 = **零收入**，不是坏账 |

C 档只能等 AWS 恢复或重启 TEE。刷新循环的 health tracker 传的是 `nil`（`ratls_refresh.go` 注释：
本进程没有可驱动的恢复路径），**不会自重置**。而**重启 TEE 会换 inbox key ⇒ 所有 provider 必须重新注册凭据** ——
这是唯一需要卖家动手的场景，且由重启引起，与轮换无关。

### 11.4 账务面

拒发发生在分配序号之前 ⇒ 不会在 provider 的序列里打洞、不对买家计费；已 relay 字节而收据拿不到时
Hub 无法结算（收据是计费前提，`hub/hub.go` 的 `Execute` 注释）。异常期只会"少收"，不会"错账"。

### 11.5 运维约束

- Hub 侧 `-tee-verify` 必须是 `attestation`。`pin` 模式信任的是部署时分发的那张叶，而轮换会换叶，
  第一次重拨就失败（`internal/mtls/mtls.go:133-139` 有专门文案提示这两种原因需要相反的处置）。
  线上证据支持生产用的是 attestation：§10 的黑窗在没有任何重新分发的情况下自愈。
- 换 TEE（新 AMI / 新 digest）与**轮换**是两回事：前者要同步 `HIVE_TEE_EXPECTED_APP` 并让 provider 重新注册；
  后者什么都不用做。

## 12. 实施记录（七）：交易所的硬边界，与"轮换还能伤到谁"的复查（2026-09-22）

§11 把轮换的影响面按买家/卖家列了一遍，并指出**唯一可能被买家看见的失败**是"复用了一条刚被退役的连接"那个
503。当时留了一句话没兑现：那不是唯一的窗口。这一节把第二个窗口关掉，并把"还有没有第三个"照着代码查完。

### 12.1 第二个窗口：在 deadline 之前开始、在它之后结束

`perform` 会把收据签名者**钉在**请求到达时的那一个（这是必要的：收据里的 KeyID 必须与承载它的连接所呈现的
epoch 一致），而入口处的 `signerStaleAt` 只在**请求开始时**判一次新鲜度。于是：

- `RequestTimeout`（`-request-timeout`，默认 2m，**设 0 就是无界**）是**从交易所自己的起点**算的窗口，
  不是"必须在签名 deadline 前结束"的约束；
- 一个在 `[deadline − RequestTimeout, deadline)` 之间被受理的请求，会在 `deadline` 之后才走到签名。

后果不是"收据不好看"，而是**结算失败**：收据 cite 的是已经在签名 margin 之外的叶，Hub 在入库前验收据
（`hub/hub.go` 的 `Execute` → `attest.Verifier.Check` → 链校验末端 `shared/snp_combined_aws.go:380` 的
`leaf.Verify`，**没设 `CurrentTime`**）⇒ `x509: certificate has expired` ⇒ 买家 5xx，而 provider 已经跑完、
Hub 无法结算。按 170 分钟的轮换周期、`RequestTimeout` 非零时有流量的情况下约 1% 以上的轮换会命中一次；
设 0 则没有上界。

### 12.2 修复（提交 `d4d8fb2`）：把签名截止变成交易所的硬边界

| 机制 | 位置 | 作用 |
|---|---|---|
| `signingHandoff = 1s` | `tee/service.go:283` | 交易所结束点到签名 deadline 之间留的余量。签名本身是微秒级，这 1s 是给调度抖动与秒级时钟粒度的地板，不是要花掉的预算 |
| `signingDeadline` / `signingBudget` | `tee/service.go:295`、`:314` | 从钉住的 signer 读出 `SNPSigningDeadline`；budget = 剩余时间 − `signingHandoff`。**没有可读叶的证据（模拟、测试假件）返回 bounded=false**，否则钉住的测试钟会被当成故障 |
| 受理时的拒绝 | `tee/service.go:393` | budget ≤ 0（余量不足 `signingHandoff`）⇒ 直接 `ErrAttestationStale`。**与"epoch 已 stale"同一位置、同一代价**：在分配 `ProviderSeq`、解开凭据之前拒绝，不给 provider 的序列打洞 |
| 交易所的硬边界 | 同上 | 否则给整个执行套一个 `context.WithTimeout(ctx, budget)`。被切断的交易所产出的是 **truncated 收据**：`Price` 对这种收据只按已交付字节收 volume（`hub/pricing.go:69-72`），于是 **provider 拿到它已做的那部分钱**，而不是整单结算不了 |
| 签名前复查（fail-safe） | `tee/service.go:701` | deadline 不是保证：忽略 context 的 transport、或跳变的时钟，仍然会走到签名。这时**拒绝而不是签**。这是唯一"provider 已经干了活却什么都结算不了"的路径，所以它的存在本身就意味着上面那条边界失效了 |

两点需要写清楚：

1. **拒绝放在受理处而不是交易所里**，是为了不产生 ProviderSeq 空洞（一个花掉却没收据的序号，provider
   无法与"被隐藏的执行"区分——见 `hub` 里那段关于 gap 的注释）。
2. **bound 总是取更紧的那一个**。它由受理时的 signer 算出，而 `perform` 钉住的 signer 在中间发生轮换时
   只会换成**更晚到期**的叶，所以这个 bound 永远不会比实际的更松；`Request.Timeout` 仍然原样传给 transport，
   两者取 min。就实际影响范围而言，需要它起作用时（`deadline − now < RequestTimeout`）切点一定落在 Hub
   `-attempt-timeout`（默认 3m）之内，所以收据总能被 Hub 读到。

### 12.3 复查发现的同类缺陷：同一个 listener 上的另外两条路径

`epochConnections.guard` 挂在 `mux` 外层，**覆盖该 listener 的所有路由**（`cmd/tee/main.go` 的
`Handler: svcRuntime.conns.guard(mux)`）。因此'退役连接 503'不只 `/v1/execute` 会遇到。逐一查过：

| 路径 | 谁在用 | 后果 | 处置 |
|---|---|---|---|
| `POST /v1/execute` | Hub 派发任务 | 买家可见的失败 | 已修（上一节，`f774d23`）：带标记的 503 重试一次 |
| `GET /v1/credential-key` | **每个** provider agent 每次重连都拉一次（经 Hub 转发） | 卖家侧：agent 注册失败，且失败原因对它完全不可见 | 已修（`865cd2c`）：把拒绝收敛成协议包里唯一的 `tee.ErrEpochRetired`，由两边共用的客户端 helper 重试一次 |
| `GET /v1/evidence/<hash>` | Hub 验收据时解析 `EvidenceHash`（**生产是 hash-only 收据**，且 `attest.Verifier` 不缓存，**每张收据都取一次**） | 三者中最重：任务跑完了、provider 付过上游了、TEE 也签了收据，Hub 却因为读不到收据自己点的证词而**把整单丢掉** | 已修（`0be5771`）：重试一次。这条不需要标记就安全——取回的是按自身哈希寻址的只读字节，且下面还会比对哈希，重试能重复的东西为零；对端真不可用则两次都失败，如实报错 |
| `GET /v1/session`（WebSocket 升级） | Hub 开流式会话 | 见 12.4 | 不加代码，理由写在 12.4 |

三条修复的**安全论证是同一个**：`guard` 在 handler 之前返回，所以那次拒绝没有分配序号、没有花凭据、没有碰
provider。差别只在"能不能证明这一点"：`/v1/execute` 上必须靠标记（无标记的 503 可能是在任务已执行之后才
回的，重试会重复执行并重复计费），`/v1/evidence` 上请求本身就是只读，规则自然满足。

### 12.4 仍未修：会话的终端收据（需要你拍板）

会话是**故意无界**的（`rotated_connections.go` 里 `track` 对 `StateHijacked` 的解释），终端收据用**结束那一刻
的 live signer** 签（`tee/service.go:989`）。如果那时 live signer 已经进了签名 margin，`Receipt()` 直接返回
`ErrAttestationStale` ⇒ `relaySession` 回一条 `{"error":...}` ⇒ Hub 侧 `sessionTunnel` 拿到的不是收据 ⇒
`ErrNoReceiptForSession`。**整个会话的字节全部无证、不可结算**，而 provider 已经把它们转发完了。

什么时候会发生：需要在**会话结束**那一刻 live signer 已过期，也就是"轮换连续失败到过了 deadline"。健康的
轮换会提前约 4m48s（AWS 在叶到期前 9m48s 重签，而 signature deadline 只提前 5m）就把新 epoch 换上，所以正常
情况下不会命中——这一条只由 AWS 侧故障触发，但**每次命中的损失是一整个会话**，不像 §11 B 档那样有 5 分钟上界。

为什么 A/B 覆盖不了它：B 的形态是"在 deadline 之前把交易所切断"，而会话的问题是**它结束的时刻由 provider
决定**，那一刻已经不能签了。唯一修法是在 live signer 距 deadline 还有 `signingHandoff` 时就**主动切断隧道**，
让收据在 margin 内签出（收据照样按已转发字节计费）。代价是这个 deadline 必须**跟着轮换走**（不能用会话开始
时那一张），需要在 relay 循环里按当前 signer 判一次——不是一行，但也不大。

三种选择：(i) 按上面实现；(ii) 接受并只留记录（它只在 AWS 已故障时出现）；(iii) 会话也加绝对长度上限
（但那会改掉"unbounded work"的设计意图，与其它部分不一致）。我倾向 (i)，但它不属于"毫秒级窗口"这一类，
所以先摆出来。

### 12.5 已确认不受影响 / 不值得改的

- **WebSocket 会话拨号（`/v1/session`）**：`hub/session.go:37` 用 `websocket.Dialer` 直拨，
  gorilla 每次自己建 TCP 连接，**不走 `http.Client` 的连接池**。所以"退役连接被复用"这个前提不成立，
  只剩 accept→请求 之间的微秒级竞态（`guard` 在轮换落在这一瞬时会拒升级，Hub 的会话循环会 `continue`
  到下一个候选后整体失败）。概率约 1e-8/天量级，低于值得加代码的门槛。**如果将来把 `Dialer.NetDial`
  指到共享 transport，这条会立刻变成真问题。**
- **空转 tick 不产生 churn**：`publishEpoch` 对已在服务的 KeyID 早返回，`adapter` 的 `supersedes` 也挡一层；
  `conns.rotate()` 只在**真的换 epoch** 时被调用一次（`ratls_refresh.go:179`，只在 `adopt` 里）。
- **Hub 候选循环的空转**：一个 stale epoch / 余量不足的拒绝会让**每个候选各打一次**（它们都指向同一个 TEE），
  N 次往返后 5xx。只是浪费，不重复计费：拒发都在分配序号之前或（fail-safe 那条）根本不出收据。
- **凭据面与轮换解耦**：inbox key 进程启动生成一次、轮换不换（`ratls_refresh.go` 的注释）；provider 的在线
  通道是 agent↔Hub 的 WS，不经 TEE TLS。真正要卖家重新注册的是**重启 TEE**，与轮换无关。
- **账务不会错**：截断收据只按已交付字节计 volume；拒发不产生收据因而无计费；`CompletionFailed` 计 0
  （`hub/pricing.go:80`）。异常期只会少收。

### 12.6 相邻但不属于轮换的两点（记录，不改）

- **TEE 侧时钟没有自检**。enclave 用的是宿主提供的 `time.Now`，而 signing deadline 来自 AWS 签发的叶的
  `NotAfter`。宿主钟若落后 AWS，TEE 会按自己的钟继续签、Hub 用真钟拒收（`certificate has expired`）——
  这是唯一**系统性**而非边界性的失效面。真要做，可以在刷新循环里用新叶的 `NotBefore` 与本地钟做一致性检查
  （AWS 只在旧叶最后几分钟才重签，所以"刚签发的叶的 NotBefore 应该接近现在"是个可判据）。
- **evidence store 是单实例磁盘、append-only**（`evidence/store.go` 的包注释）。轮换只是往里加文件（每
  ~2h 一个，几 KB）；真正会丢历史的是**换 TEE 实例**，那时 hash-only 收据的证词只能靠别处的副本解析。
  与轮换无关，与"换机/重新部署"有关。

### 12.7 验证

- `go vet ./shared/... ./tokenhive/...`：无输出。`go test ./shared/... ./tokenhive/...`：全绿。
- harness A/B（`/tmp` 干净 worktree，基线 `f774d23`）：`d4d8fb2` 与 `865cd2c` 都是
  **18 场景 / 31 OK / 0 FAIL，断言逐行相同**。
- 新增测试：`tee/exchange_bound_test.go` 5 个（bound 的取值与 `RequestTimeout` 并存；被切断仍出可结算的
  truncated 收据；余量不足时在 transport 与序号之前就拒；逃出 bound 的交易所不签名；无可读叶时不设 bound）；
  `hub/tee_test.go` 2 个（credential-key 的标记重试一次 + 不循环）；`evidence/store_test.go` 2 个
  （evidence 抓取重试一次 + 持续拒绝则报错）。
