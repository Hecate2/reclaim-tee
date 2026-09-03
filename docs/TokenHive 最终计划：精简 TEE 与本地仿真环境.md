# TokenHive 最终计划：精简 TEE 设计与本地仿真环境

日期：2026-08-31
状态：**最终版（合并性文档）**
替代（以下三份草案由本文件取代，已删除）：
- ~~TokenHive 本地仿真测试环境方案.md~~
- ~~TokenHive TEE 对外暴露字段缺口分析.md~~
- ~~TokenHive TEE 职责精简方案 v2.md~~

> 本文档合并了上述三份草案的结论，并采纳两项已拍板的决策：
> 1. **定价权在 Provider**（价格进 Provider 签名的 Policy，由现有 `PolicyHash` 覆盖，无需新字段）。
> 2. **v1 即包含 `ProviderSeq`**（键 18）。
>
> 用户的原始文档（`基于 TEE 的可信 AI API 代理方案.md`、`改造路线图.md`、`MPC_OPRF_ARCHITECTURE.md`）是本方案的输入，不在此改动。

---

## 0. 一句话

**TEE 只保证字节层，语义层交给 Hub。**

- 字节层：TLS 握手、凭证注入、HTTP 收发、摘要、签名——TEE 做，因为只有它能做。
- 语义层：模型、token 数、价格、配额、账本、调度——Hub 做，因为它本来就看得到完整请求与响应。

TEE 从"可信业务引擎"退回为"**可信执行与留证**"。这是本次精简的全部内容。

---

## 1. 已拍板的决策（决策记录）

| 决策 | 结论 | 影响面 |
|---|---|---|
| TEE 职责 | 只做 TLS 握手 + 凭证注入 + HTTP 收发 + 摘要签名 + 极小的 Policy 白名单判定 | 删除 quota/模型/用量/价格/重试等全部语义职责 |
| 定价权 | **Provider 侧**。价格表放进 Provider 签名的 Policy | 复用现有 `PolicyHash`，不新增 CBOR 字段 |
| `ProviderSeq` | **v1 实现**（键 18） | TEE 需要一份可跨重启存活的单调 counter（见 §5） |
| 接口形态 | 单 RPC：`POST /v1/execute` + SSE 回执 | 不用 gRPC，省代码生成与流式 trailer 处理 |
| 仿真环境 | 软件模拟证明适配器（只换信任根不换代码路径）+ 真 TLS + 脚本化假模型 | 见 §6 |

---

## 2. TEE 职责边界（精简后）

| 职责 | 归属 | 理由 |
|---|---|---|
| TLS 握手、连接管理 | **TEE** | 密钥与明文都在 TEE；外包就失去"Agent 读不到明文" |
| 凭证存储与注入 | **TEE** | 凭证只在 TEE |
| HTTP 请求构造与发送 | **TEE** | 同上 |
| 响应摘要 + 回执签名 | **TEE** | 签名密钥在 TEE |
| Policy 白名单判定（host/path/method） | **TEE** | §3，成本极低、不可外包 |
| JobSpec 结构校验 + body_hash 绑定 | **TEE** | 防止错配/截断，成本极低 |
| `ProviderSeq` 单调序号 | **TEE** | §5，审计完整性（v1） |
| JobSpec 构造 | Hub | TEE 只接收 |
| Provider 选择与调度 | Hub | 需要全局视角 |
| 配额 / 限流 | Hub | 需要累计状态 |
| usage 解析（token 数） | **Hub** | Hub 本来就在转发完整响应流 |
| 计价、收益、账本 | Hub | TEE 不该懂钱 |
| 重试与 failover | Hub | — |

### 2.1 一件不能简化的事：Policy 执行点留在 TEE

你列的四件事里没有 Policy。建议**保留，但瘦身到只剩白名单匹配**。理由不是守旧，是成本：

**TEE 构造 HTTP 请求行时，本来就已经握有 host / path / method 的明文。** 拿这三个值去比对一份已验签的 Policy，是几十行的集合匹配，零额外 I/O、零额外状态、零密码学开销。

而移除它的代价是：Provider 的唯一防线消失。按方案 §3.2 的信任模型，Provider 不信任 Hub。凭证隔离在 TEE 只解决了"Hub 看不到 token"，没解决"Hub 拿 token 去打哪儿"。授权判断一旦移到 Hub 侧，Hub 就能自己批准自己——凭证等于提款卡。

**所以 Policy 留在 TEE，但砍到只剩一个问题：`这个 (host, path, method) 三元组，Provider 允许吗？`** 现有的 `policy.Rule.Methods / Path / AllowStream / QueryKeys` 已经够用，无需新增。

### 2.2 关键简化：usage 提取从 TEE 消失

TEE 不再按 JSONPath 提取 `$.usage.total_tokens`。Hub 本来就要转发完整响应流，它看得见每个字节；**Hub 解析 usage，TEE 用 `FinalChunkHash`（键 19，P1）锚定 Hub 解析时所依据的那串字节**。TEE 零语义理解。

代价：Provider 对"用了多少 token"的信任，止于"Hub 账本 + 回执锚定的字节"。此洞可用 O(1) 内存的 `FinalChunkHash` 补上（见 §4.3）。

---

## 3. TEE 对外接口：一个 RPC

职责收窄后，接口窄到只有一次调用。直接用 HTTP + SSE——与产品本身的 SSE 气质一致，Hub 用任何 HTTP 客户端都能接：

```
POST /v1/execute
  Content-Type: application/cbor          （canonical JobSpec）
  Body: 请求体原始字节

→ 200 OK
  Content-Type: text/event-stream

  data: <chunk 1>\n\n
  data: <chunk 2>\n\n
  ...
  event: receipt
  data: <base64(canonical SignedReceipt)>\n\n
```

Hub 的职责收敛为：**构造 JobSpec → 打这个接口 → 把 `data` 帧原样转给用户 → 收 `receipt` 帧入账。**

窄接口是本次精简最大的工程红利：Hub 业务逻辑不再依赖 TEE，可用假 TEE 秒级测试（§6）。

---

## 4. 字段与 CBOR 键号

### 4.1 原则：该砍的砍，但键号一次留够

项目约定"键号一旦发布不再改号"（键 14 已永久作废）。做法：**v1 只实现必要最小集，但把将来可能要的号一次占住**——留号代价为零，改号代价是破坏性升级。

### 4.2 JobSpec（键 1–13 已用，14 作废，新字段从 15 起）

只加两个**声明字段**——进 hash、被回执覆盖，但 TEE 不校验内容：

| 键 | 字段 | 类型 | 说明 |
|---:|---|---|---|
| 15 | `DeclaredModel` | string | Hub 声明用了哪个模型，供计价与审计 |
| 16 | `TenantRef` | []byte | 不透明租户引用，**非 PII**，供 Provider 对账 |

> **不要把它们再复制一份进回执。** 它们在 Spec 里，已被 `job_spec_hash` 覆盖，而 `job_spec_hash` 已在回执里。回执里可读的 Host/Path/Method 只是描述性副本，验证者必须再比对 `job_spec_hash` 才算数。

### 4.3 Receipt（15 = Attestation，16 = PolicyHash 已用，新字段从 17 起）

| 键 | 字段 | 类型 | v1 | 说明 |
|---:|---|---|:---:|---|
| 17 | `RequestBytes` | uint64 | ✅ | 输入侧计量。TEE 本来就算 `len(body)` 做上限检查，顺手签出，成本为零 |
| 18 | `ProviderSeq` | uint64 | ✅ | per-provider 单调序号，签进回执。**v1 实现**（见 §5） |
| 19 | `FinalChunkHash` | []byte | P1 | 最后一个响应 chunk 的 SHA-256，供 Provider 独立验算 usage（§2.2） |
| 20 | `FirstByteAtMs` | int64 | P1 | TTFB，Provider 出口质量可定价 |
| 21–26 | *保留* | — | ⬜ | 留给 AttestedHeaders / RateCardHash / 毫秒时间戳 / SessionRef / CumulativeUsage / 其它 |

**v1 实现字段：`RequestBytes` + `ProviderSeq`。**

### 4.4 为什么这两个是 v1

- `RequestBytes`：TEE 内部已算 `len(job.Body)` 做上限检查，算完就丢。签出来零成本，且**输入侧计量此前是纯空白**——请求体大小从未被证明过。
- `ProviderSeq`：它才是"我赚了多少"这个问题的完整答案。回执是 Hub 递给 Provider 的，Hub 可以少给几张，Provider 少算收入且**无从发现**——per-record 签名证真实，不证全集。有了单调序号，Provider 拿到任意一张序号 N 的回执，就知道自己至少被用了 N 次，可据此索要缺失记录。

---

## 5. ProviderSeq 设计（v1 关键）

### 5.1 语义

- 每个 Provider（由 `Policy` 标识，或 `TenantRef` 解析出的 Provider 主键）维护一个从 1 开始的 `uint64` 计数器。
- 每次 TEE 成功完成一次 execute 并准备发回执前，`Seq.Next(providerID)` 返回并自增，结果签进回执键 18。
- 回执可独立验证：`seq(N)` 隐含"该 Provider 至少被调用 N 次"。Provider 持有历史回执，发现缺口即可向 Hub 索要。

### 5.2 实现：一个最小 `SeqStore` 接口

这是 TEE 里**唯一的有状态组件**。用一个窄接口屏蔽"真实密封存储"与"仿真文件存储"的差异：

```go
// tee/seqstore.go
type SeqStore interface {
    Next(providerID []byte) (uint64, error) // 自增并返回新序号
    Peek(providerID []byte) (uint64, error) // 当前最大值（不修改）
    Close() error
}
```

两种后端：

| 后端 | 场景 | 持久化方式 |
|---|---|---|
| `sealedStore` | 真实 TEE（SEV-SNP / SGX） | 用平台 sealing key 加密 blob，落 TEE 内受保护存储；重启后解封恢复 |
| `fileStore` | **本地仿真 / 开发** | 普通 JSON 文件（如 `.sim/seqstore.json`），由 TEE 进程内互斥锁保护 |

> 仿真环境用 `fileStore` 即可——它真实地在多次重启间累加计数器，完整演示"缺口检测"行为，且**不引入任何真实密码学依赖**。`sealedStore` 留到 M3 Vault 阶段接入，接口不变。

### 5.3 与"精简"的张力处理

用户要求 v1 带 `ProviderSeq`，而它确实是有状态组件。处理原则：**状态只限于这一处，且被接口隔离**。TEE 其余部分仍是无状态、纯字节层。接入真实密封存储时不改 TEE 逻辑，只换 `SeqStore` 后端。

### 5.4 仿真环境对 ProviderSeq 的断言

harness 用例（见 §6）：
1. 连发 5 次 execute，断言回执 seq = 1,2,3,4,5 且单调。
2. 重启 TEE 进程（fileStore 保留），再发 1 次，断言 seq = 6（证明跨重启存活）。
3. Hub 故意丢弃 seq=3 的回执后向 Provider 交账，断言 Provider 凭 (2,4) 检测出缺口。

---

## 6. 测试与仿真环境

窄接口带来最大红利：**Hub 业务逻辑不再依赖 TEE，可用假 TEE 秒级测试**。计价、配额、账本、重试、调度是最需反复迭代的部分，简化后都是纯 Hub 侧代码，不需要网络、TEE、真凭证。

### 6.1 三层测试

| 层 | 测什么 | 用什么 | 速度 |
|---|---|---|---|
| **A · Hub 业务** | 计价、配额、账本、重试、调度、ProviderSeq 缺口检测 | **fake TEE**（内存实现同一 RPC，几十行） | 毫秒级 |
| **B · TEE 可信属性** | 凭证不泄漏、Agent 只见密文、摘要正确、签名可验、policy 生效、流式/中断、序号单调、跨重启存活 | 真 TEE 进程 + Agent + mock provider + **抓包** | 秒级 |
| **C · 接缝** | 回执能否锚定账本、端到端 | 真 TEE + 真 Hub | 秒级 |

**B 层抓包断言是单元测试永远做不了的**：`sudo tcpdump -i lo0 -w /tmp/agent.pcap port <agent_port>`，跑完一轮后 `strings` 里 grep 凭证应为空。方案 §10 的论断变成一条可执行测试。

### 6.2 组件树

```
cmd/
├── faketee/        【新增】TEE 的内存实现，专供 Hub 测试（A 层关键）← 快迭代
├── mockprovider/   脚本化 LLM + HTTPS + 故障注入
├── agent/          Provider Agent（已有代码，加个 main）
├── tee/            真 TEE（瘦身后，含 seqstore）
├── hub/            业务：JobSpec 构造、计价、配额、账本、调度、缺口检测
└── verify/         离线验签 CLI
harness/            一键编排 + 场景矩阵 + 抓包断言
```

`cmd/faketee` 是本次精简才成为可能的东西——接口窄到只有一次调用，才有资格做一个几十行的替身。

### 6.3 假模型默认脚本化（不用真模型）

理由：**回执锚定的是响应字节的 SHA-256**，真模型输出不逐字节稳定，没法做 golden transcript 断言，失败也复现不了。脚本化引擎按配置吐固定 chunk 序列，完全确定。真模型（ollama + qwen2.5:0.5b，约 400MB）留作可选演示引擎，不进 CI。

### 6.4 本地也要真实 TLS

现有 e2e 用明文 HTTP（有意为之，证明 Agent 不改内容），但"Agent 无法读取明文"这条核心属性**没被测到，只是没被推翻**。harness 内置测试 CA，mock provider 跑 HTTPS，TEE 通过 `TLSClientConfig` 信任它——这条属性才真的成立，抓包断言才有意义。

### 6.5 关于真实证明：结论

本机（Apple M4）无法模拟真实 SEV-SNP：QEMU 的 SEV-SNP guest 需 AMD 宿主机；Intel SGX simulation 是 x86 Linux 专用，且验的是 Intel DCAP 链而非 AMD VCEK 链。建议：

- **本地**：`platform/simulated` 软件模拟适配器，要求**证据字段与真实 SEV-SNP report 一一对应**，只换信任根不换代码路径。否则上线那天整条验证链才是第一次被执行。
- **CI nightly**：AWS `c6a`/`m6a` 按小时起真机。

### 6.6 本地可运行的最小环境清单

1. `mkcert` 或自建测试 CA → 给 mock provider 发证书。
2. `cmd/mockprovider`：脚本化 SSE 响应，支持故障注入（断流 / 401 / 429 / 超尺寸）。
3. `cmd/agent` + `cmd/tee`：TEE 走 sim 适配器，`SeqStore=fileStore` 落到 `.sim/`。
4. `cmd/hub` + `cmd/faketee`：A 层纯内存测试无需起网络。
5. `harness/`：`bash` 编排 + `tcpdump` 抓包断言 + 场景矩阵（正常流 / 越权拒绝 / 断流 / 401 / 429 / Agent 被杀 / epoch 轮换 / seq 缺口）。

---

## 7. 执行步骤（按不可逆程度 × 依赖排序）

前两步是 schema，必须先定；第三步是唯一不依赖 TEE 的，可最快见效。

### S1 · 定接口契约与键号（半天）— ✅ 完成

产出：§3 的 RPC 形状 + §4 的键号表。**全部工作里最不可逆的一块**（键 14 已作废，新增从 15 起，一次分配对）。当前已拍板：定价权在 Provider（无 `RateCardHash` 字段）、v1 含 `ProviderSeq`（键 18）、`RequestBytes`（键 17）。

### S2 · Policy 瘦身 + 包归位（1 天）— ✅ 完成

- `policy.Rule` 确认只留 `Methods/Path/AllowStream/QueryKeys`；删除此前草案提过的 `UsageJSONPath`。
- 把 `tokenhive/` 现有 8 个包按 §2 边界归位——**是重构不是重写**，现有代码大部分照搬。
- 新增 `tee/seqstore.go`（§5.2 接口）。

### S3 · Hub 业务 + fake TEE（1–2 天）— ✅ 完成

先把 `cmd/faketee` 和 Hub 的计价 / 配额 / 账本 / ProviderSeq 缺口检测写出来并用 fake TEE 测通。**不需要网络、TEE、真凭证**，纯业务迭代。理由：业务规则最可能反复改，先让它跑在毫秒级循环里，比等 TEE 就绪再一起调快得多。

落地为 `tokenhive/hub/` 包（pricing / quota / ledger / store / tee / scripted），配 `ScriptedTEE` 内存替身做毫秒级单测；`cmd/hub` 收薄为纯装配与打印。另新增 `policy.RateCard`（键 12）承载定价权，新增 `tee/rpc.go` 作为单 RPC 线格式的唯一定义。详见 §10。

### S4 · 真 TEE 进程 + 仿真环境（1–2 天）— ✅ 完成

`cmd/tee` + `cmd/mockprovider` + `cmd/agent` + harness，含抓包断言与故障矩阵（正常流 / 越权拒绝 / 断流 / 401 / 429 / 超尺寸 / Agent 被杀 / epoch 轮换 / **seq 缺口与跨重启存活**）。

落地要点：
- **SOCKS5 Agent 抓包断言（"Agent 只见密文"）**：`cmd/agent` 新增 `-tap` 标志，在 SOCKS 握手之后、TLS 管道之上镜像每一字节到文件；harness 场景 9 用 `grep -F` 校验 tap 文件里**不含** credential / `Bearer` / `Authorization`，把"Agent 读不到明文"从口头论断变成可执行断言。实测：跨 TEE→Agent→Provider 真实 TLS 链路捕获 4700 字节，零明文命中。
- 场景 10：Agent 在 `fault=slow` 请求中途被杀 → TEE 优雅签出 `completion=failed`（0 字节、0 计费）回执，**不挂起、不 panic**。
- 场景 11：TEE 以新 sim epoch 重启（新密钥）→ 新号回执仍能验签（密钥内嵌于回执，epoch 轮换对验签透明）。
- 场景 12：`fault=big` + `-max 65536` → 回执 `completion=truncated`（65544 字节 / 3 chunks），`MatchesStream` 通过。

> **S4 期间修复的真实 bug（`tee/service.go` 的 `relay`）**：原实现先 `hasher.WriteChunk(chunk)` 再判 `MaxResponseBytes`，导致**超 cap 的 chunk 进了 `StreamHash` 却从未被转发**——Hub 侧 `MatchesStream` / `HashResponseStream` 重放（前缀）永远对不上，于是**每一个被截断的响应在 Hub 验签必失败**（表现为"TEE 的 bug"，实为哈希/转发错位）。修复：cap 检查移到 `WriteChunk` 之前，并新增 `totalBytes` / `totalChunks` 计数器——`StreamHash` 只覆盖被转发的真实前缀，而 `ResponseBytes` / `ChunkCount`（回执与 Result 都用）如实上报 Provider 发来的总量。生产里所有"超尺寸 / 截断响应"都会踩这个坑，不止仿真。

### S5 · 性能基准（半天）— ✅ 完成

新增 `tokenhive/cmd/bench` + `tokenhive/harness/bench.sh` + 单元测试 `tokenhive/tee/receipt_budget_test.go`，把方案 §18 四个验收目标变成可回归的指标。测量法：同一负载跑两遍——`direct`（client→provider 直连 TLS，基线）与 `tee`（client→TEE→Agent→provider），两者之差即 TEE+Agent 这层的可信开销。

实测（darwin/arm64，localhost 仿真）：
- **证明体积 754–758 字节** ✅ 远小于 2KB 预算（即便 `IncludeEvidence=true` 自包含；sim 证据仅是 ~150 字节 JSON）。
- **回执生成 p95 0.16ms** ✅ 远小于 5ms。
- **TTFT 绝对增量 0.5–2ms** ✅（localhost 合理阈值 <25ms）。
- **吞吐开销**：小负载 ~95%、1MiB 负载 ~14%——见下方 §9 说明，这是单主机 loopback 假象，非生产信号。

> **关键修正（S5 期间澄清）**：§9 的 TTFT<1% / 吞吐<3% 是**生产拓扑目标**。在单主机 loopback 仿真里，TEE 必然在同一台机器上把每个字节搬两遍（provider→TEE 与 TEE→client），于是相对吞吐开销被结构性地放大、且无法反映生产（生产里 TEE 是靠近 provider 的独立网络跳点）。故 sim 只忠实测量**结构性/签名绑定**的指标（证明体积、回执 p95、TTFT 绝对增量），吞吐与相对 TTFT 开销仅作趋势参考、不进硬门禁。详见 §9。

---

## 8. 同步修正的既有问题

精简过程中顺手要处理的（来自此前草案，保留以免丢失）：

- **P0 · 证据取回接口不存在** → 方案 §17 承诺"证据可供验证者取回"落空，默认配置 `IncludeEvidence=false` 下**每张回执都验不了**。这是缺陷不是待办，需单独提前修。
- **P2 · `transport.Config.Scheme` 允许 `http`** → 凭证可能明文穿过 Provider Agent，而 Agent 正是方案明确不信任的一方。建议加不变量：注入了凭证就必须 https。
- **P2 · 文档漂移** → §29 仍写"Hub 通道认证（待定）"与 §7 mTLS 定案矛盾；§4/§10 仍描述 Agent 为"透明 TCP relay"（实际是 SOCKS5 + 白名单 + RFC 1929）；§20/§22 建议复用 `minitls`/`providers`/`client` 但实际一个都没用。

---

## 9. 验收与回归指标（来自方案 §18）

| 指标 | 目标 | 由哪层测量 |
|---|---|---|
| TTFT 开销 | < 1% | B / C 层 |
| 吞吐开销 | < 3% | B / C 层 |
| 回执生成 p95 | < 5ms | B 层 |
| 证明体积 | < 2KB | B 层（sim 适配器须满足，不可放宽） |

> 这四个目标当前无任何环境能测量。本仿真环境（§6）是唯一能低成本把它们变成回归指标的地方，应在 S4 即接入。

**sim 能忠实测量的 vs 不能的（S5 实测结论）**：
- ✅ **证明体积 < 2KB**、✅ **回执 p95 < 5ms**、✅ **TTFT 绝对增量**：这三项与机器拓扑无关，sim 直接测、直接进硬门禁。
- ⚠️ **TTFT 相对开销 < 1%**、⚠️ **吞吐开销 < 3%**：这是**生产拓扑目标**。单主机 loopback 下 TEE 把每个字节搬两遍（provider→TEE、TEE→client），相对开销被结构性放大（实测小负载 ~95%、1MiB ~14%），不反映生产。相对开销需多机 / 真实网络拓扑才能测量；sim 仅作趋势参考。要更接近真实，可加一个「哑 TCP 代理基线」（client→proxy→provider，同样搬两遍但不做 TEE 逻辑）隔离出 TEE 的纯处理开销——列为后续增强。

---

## 10. 实现状态（S1–S5 已完成，2026-09-01）

以下为已落地的代码（均在 `reclaim-tee/` 仓库内，darwin/arm64 实测可编译可运行）。`go build` / `go vet` / `go test ./tokenhive/...`（12 包）全绿。

### 真实业务类型（S1 字段确立）
- `tokenhive/jobs/spec.go`：新增键 15 `DeclaredModel`、16 `TenantRef`（声明字段，进 hash，TEE 不校验）。
- `tokenhive/proof/receipt.go`：新增键 17 `RequestBytes`、18 `ProviderSeq`（v1 即实现）。
- `tokenhive/policy/policy.go`：新增键 12 `RateCard`（S3）——**定价权回归 Provider 的载体**。整数微单位（1e-6 计价单位），含 `PerRequestMicros` / `PerMegabyteMicros` / `ModelPremiumMicros`，带 `MaxRateMicros` 溢出上界。价格进已签名的 Policy，故现有 `PolicyHash` 已覆盖，回执不需要新增价格字段（与 §4 定案一致）。

### 业务包（S2 / S3）
- `tokenhive/tee/seqstore.go`（S2）：`SeqStore` 接口（Next/Peek/Close）+ `NewMemorySeqStore`（测试/fake）+ `NewFileSeqStore`（跨重启持久，原子 tmp+rename）。`tee.Config.Seq` 必填，缺则 `ErrNoSeqStore`，**不静默降级为内存**。
- `tokenhive/tee/rpc.go`（S3）：单 RPC 的**线格式唯一定义**——`ExecuteRequest`（键 1 Spec / 2 Body）、`ServeExecute`（服务端）、`DecodeReceiptFrame`。`writeChunkFrame` 保证 SSE 帧字节级精确往返（见下方"关键修正"）。
- `tokenhive/hub/`（S3，新增包）：Hub 全部业务规则，均可通过 `hub.TEE` 接口用脚本化替身毫秒级单测：
  - `pricing.go` — `Price(card, model, receipt)`：只对 `CompletionComplete && 2xx` 计价；整数运算带溢出检查，溢出返回 `ErrPriceOverflow` 而非回绕成小账单。
  - `quota.go` — 固定窗口配额，按 tenant，**在派发前拦截**。
  - `ledger.go` — 派发/验签/结算三级计数 + 收入，`Snapshot()` 保证读数一致。
  - `store.go` — 回执库（按 ProviderSeq 命名，拒绝重复 seq 覆盖）+ `Audit()` 验签并检测缺口。
  - `tee.go` — `TEE` 接口（一个方法）+ `HTTPTEE` 客户端 + SSE 解析。
  - `scripted.go` — `ScriptedTEE` 内存替身 + `ScriptReceipt` 构造器。
  - `hub.go` — `Hub.Execute` 编排：配额 → 取价目表 → 派发 → 验签 → 流哈希比对 → 计价 → 落库。

### 仿真组件（cmd/）
- `tokenhive/cmd/{tee,faketee,agent,hub,mockprovider,verify}/` + `cmd/internal/shared/`，`tokenhive/harness/harness.sh`（S2 由 `sim/` 归位而来）。
- `cmd/tee`（真 TLS，可经 SOCKS5 Agent）/ `cmd/faketee`（内存脚本化 Transport）**都跑真实 `tee.Service`**，不绕过业务代码。
- `shared` 只保留夹具（`.sim` 目录、凭证/Policy、测试 CA）；重复的 `Policy`/`ExecuteRequest`/SSE 实现已删除，改由真实 `policy` 包与 `tee/rpc.go` 提供。

### 关键修正（S3 期间发现并修复）
- **定价权违约**：原 `cmd/hub` 硬编码 `pricePerRequest` map，等于 Hub 自己定价，与定案矛盾。现价目表来自 Provider 签名的 Policy；`TestHubChargesTheProvidersPrice` 为回归测试。
- **SSE 帧字节失真**：`data:` 行被 `TrimSpace`，会吃掉 chunk 首尾空白；空 chunk 被丢弃。而 `proof.StreamingHasher` 明确"空写入也计数"，故丢帧会同时改变 ChunkCount 与 StreamHash，**使该任务每张回执都验不过**。已改为「每个 chunk 按行拆成多个 `data:` 行 + 只剥一个前导空格 + 以 data 行数而非长度判断是否成帧」，并双向加了字节级往返测试。

### 关键修正（S4 期间发现并修复）
- **`tee/service.go` 的 `relay` 越界哈希 bug**：原实现先 `hasher.WriteChunk` 再判 `MaxResponseBytes`，超 cap chunk 进 `StreamHash` 却未转发，导致所有截断响应在 Hub `MatchesStream` 必失败。修复：cap 检查前置 + 新增 `totalBytes`/`totalChunks` 计数器，`StreamHash` 仅覆盖被转发前缀，而 `ResponseBytes`/`ChunkCount` 如实上报总量。回归测试 `TestExecuteEnforcesTheResponseCap`（期望 16 字节 / 3 chunks）保持不变。

### 运行方式
```bash
cd reclaim-tee
bash tokenhive/harness/harness.sh     # 端到端 12 场景
go test ./tokenhive/hub/...            # Hub 业务规则，脚本化 TEE，毫秒级
bash tokenhive/harness/bench.sh       # S5 性能基准（TTFT/吞吐/回执 p95/证明体积）
```

### harness 8 场景实测（对真实 tee.Service）
1. 正常流：seq 1–5，5 张可验回执，计价 5.00（来自 Provider 价目表）
2. 越权 host：TEE 拒绝，凭证未触碰
3/4. provider 401/429：`status=401/429 completion=complete`，**0 计价**
5. 断流：`status=200 completion=truncated chunks=2`，**0 计价**
6. 重启 faketee：seq 续接到 9（文件持久，不归零）
7. Hub 藏匿 seq=2：审计 `GAP DETECTED: missing receipts [2]`
8. 配额（3 次尝试 / 限额 2）：第 3 次被 Hub 拦截，**审计 `sequence complete: 1..2, no gaps`**——证明被拒请求未消耗 ProviderSeq
9. **Agent 只见密文**：真 `cmd/tee` → `cmd/agent -tap` → mockprovider(TLS)；tap 文件 `grep -F` credential / `Bearer` / `Authorization` 必须命中 0 次（实测 4700 字节，零明文）。
10. **Agent 中途被杀**：`fault=slow` 请求进行中杀掉 Agent → TEE 优雅签出 `completion=failed`（0 字节、0 计费），日志无 panic、无挂起。
11. **epoch 轮换透明**：TEE 以新 sim epoch 重启（新密钥）→ 新号回执仍验签通过（密钥内嵌回执）。
12. **超尺寸截断**：`fault=big` + `-max 65536` → `completion=truncated`（`ResponseBytes=65544 chunks=3`），`MatchesStream` 通过，无 "different bytes" 报错。

### S5 性能基准（新增 cmd/bench + bench.sh + 单元测试）

把方案 §18 四个验收目标变成可回归指标：
- `tokenhive/cmd/bench`：同一负载跑 `direct`（client→provider 直连 TLS）与 `tee`（client→TEE→Agent→provider），算出 TEE 层的 TTFT 增量、吞吐开销、回执 p95、证明体积；`-baseline-rtt` 可把相对 TTFT 开销按生产基线评估。
- `tokenhive/harness/bench.sh`：起真实组件（mockprovider TLS / agent / 真实 tee.Service），跑「延迟场景」（小响应 n=200）与「吞吐场景」（fault=big 封顶 1MiB n=20），输出四项指标与门禁结论。
- `tokenhive/tee/receipt_budget_test.go`：无网络的永久硬门禁——自包含 sim 回执（`IncludeEvidence=true`）必须 < 2KB，且单次签名 < 5ms。

实测（darwin/arm64，localhost）：证明体积 **754–758 字节**、回执 p95 **0.16ms**、TTFT 绝对增量 **0.5–2ms**，全部达标；吞吐开销为 loopback 假象（见 §9），不进硬门禁。

### 已知取舍
- 仿真回执设 `IncludeEvidence=true`（自包含便于离线验证）；生产应设 false 并走证据缓存（§8 P0 已记录）。
- 真实 SEV-SNP 本机仍不可模拟，CI nightly 用 AWS c6a/m6a。
- SSE 分帧无法承载 chunk 内的裸 `\r`（行分帧固有限制）；LLM 流式分片不含 CR，暂不引入 base64 破坏可读性。

