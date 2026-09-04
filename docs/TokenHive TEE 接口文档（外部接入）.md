# TokenHive TEE 接口文档（外部接入）

版本：2026-09-04 · 对应代码分支 `local-sim`（本次核对基于当前代码，非历史设计稿）

本文档面向**外部公司/团队接入 TokenHive TEE**：说明 TEE 暴露了哪些接口、线上字节格式、回执如何验签、凭证如何被约束，以及接入时必须做对的校验。所有字段、键号、错误语义均以代码实现为准；凡与早期设计文档冲突之处，以本文档为准（差异处已标注）。

---

## 0. 读者与三种接入角色

| 角色 | 你要做什么 | 你关心的章节 |
|---|---|---|
| **调用方**（自建 Hub / 平台方，直接调用 TEE） | 构造 JobSpec，POST `/v1/execute`，或开会话 `/v1/session`；接收流式字节与回执 | 第 2–8、11 章 |
| **Provider（卖家）** | 把自己的 AI 服务 token 交给平台；关心 token 被用在哪些接口、如何审计 | 第 7、10 章 |
| **Provider Agent（出口代理）** | 在自己网络上跑出口代理进程，让 TEE 经你的网络出口访问 AI 服务商 | 第 10.3 节 |

**不属于本文档**：Hub 面向终端用户的 OpenAI 兼容 API（`/v1/chat/completions`、`/v1/responses`、`/v1/messages`）。那是 Hub 侧接口，见第 12 章的说明。

### 术语

- **TEE**：执行环境。**不持久化任何 Provider 凭证**；每个作业随 JobSpec 携带一份用 TEE 公钥加密的凭证信封，TEE 在飞地内按作业解密、注入请求，执行完即丢弃。它发起真实上游请求、签发执行回执，但**不理解业务语义**：不解析 JSON、不知道模型、不定价。
- **Hub**：业务侧。调度、定价、配额、账本、回执存储都在 Hub。本文档的"调用方"通常就是 Hub。
- **Job / JobSpec**：Hub 交给 TEE 的一次执行请求描述（第 4 章）。
- **Receipt（回执）**：TEE 对"这次交换确实发生、字节就是这些"的签名证明（第 7 章）。
- **ProviderSeq**：TEE 为每个 Provider 维护的单调序号，签进回执（键 18）。序号缺口 = 有执行被隐藏。
- **canonical CBOR**：所有进入哈希/签名的结构都用确定性 CBOR 编码（第 3 章）。

---

## 1. 端点总览

| 端点 | 方法 | 用途 | 请求 Content-Type | 响应 |
|---|---|---|---|---|
| `/v1/execute` | POST | 一次性执行：TEE 用 Provider 凭证发一次上游请求，流式回传字节，末尾给回执 | `application/cbor` | `text/event-stream`（chunk 帧 + `receipt`/`error` 帧） |
| `/v1/session` | GET（WebSocket Upgrade） | 长会话（Realtime 类）：Upgrade 后双向透传字节，结束时给会话回执 | — | WebSocket：Binary 帧透传，Text 帧为控制/回执 |
| `/v1/credential-key` | GET | **凭证平面**：发布 TEE 的收件公钥（InboxKey 公钥半），供 Provider Agent 拉取后用其加密自己的 token | — | `application/json`（`key_id` + `public_key`，base64） |

**凭证平面说明**：这是 TEE 上唯一与凭证相关的端点，**只发布公钥**。TEE 不提供任何查询/写入凭证的端点——它根本没有保存凭证的地方。登录的 Agent（经 Hub 的 AgentGate）拿到此公钥后把 token 加密成信封，Hub 只中转这个密文信封并存入自己的凭证库，再随每次作业上报给 TEE；只有 TEE 手里的私钥能解开（详见 7.4）。

**监听地址**：由部署方决定。本地仿真默认 `127.0.0.1:18090`（`cmd/tee -addr`），真实部署以交付的部署配置为准。

**传输与鉴权现状**（重要，接前请确认）：

| 通道 | 现状 |
|---|---|
| Hub → TEE | **当前无应用层鉴权**。生产环境应在**部署层启用 mTLS**（TEE 侧 `platform/sevsnp` 适配器提供 `ServerTLSConfig()`）；代码内 `tee.Config.SubmitterVerifier` 是可选钩子，用于将来加应用级 Hub 身份校验，默认不启用。 |
| TEE → AI 服务商 | TLS ≥ 1.2，**ALPN 锁定 `http/1.1`**（显式连接模型的前提，第 9 章） |

---

## 2. 编码规则（canonical CBOR）

所有进入哈希或签名的结构（JobSpec、Receipt、Policy）都用**确定性 CBOR**（RFC 8949 §4.2.1 核心确定性编码）：

1. 整数与长度用**最短形式**；
2. map 的**键按其编码字节排序**；
3. **绝不产生不定长（indefinite-length）项**；
4. 结构一律用**整数键**（`cbor:"1,keyasint"`），而非字段名——因此字段改名不影响线上格式。

**解码方必须拒绝非 canonical 编码**。否则同一份逻辑内容会算出不同哈希，验签必然失败（这是设计上的防篡改手段，不是苛刻要求）。

### 2.1 各语言的对接方式

- **Go 接入方**：直接 import 非 internal 包并使用其方法，无需自己实现编码器：
  - `tokenhive/tee`：`ExecuteRequest.EncodeCanonical()`、`DecodeExecuteRequest()`、`SessionRequest.EncodeCanonical()`、`DecodeReceiptFrame()`、常量 `ExecuteContentType` / `EventReceipt` / `EventError`
  - `tokenhive/jobs`：`Spec.EncodeCanonical()`、`Spec.Hash()`、`HashBody()`
  - `tokenhive/proof`：`Verify()`、`SignedReceipt`
  - `tokenhive/policy`：`Policy` / `Set`（仅当你也运行 TEE 侧）
- **非 Go 接入方**：`tokenhive/internal/canonical` 是 Go internal 包，外部**无法导入**。请按上述四条规则用你语言的 CBOR 库实现确定性编码（例如 Go 的 `fxamacker/cbor` 用 `CoreDetEncodingOptions`；其它语言需配置"最短长度 + 键排序 + 禁用不定长"）。

### 2.2 域分隔哈希常量

同样的字节在不同语境下必须得到不同摘要，所以每个哈希都带域前缀：

| 域 | 常量值 |
|---|---|
| JobSpec 哈希 | `TokenHive.JobSpec.v1` |
| 请求体哈希（BodyHash） | `TokenHive.RequestBody.v1` |
| 执行回执签名 | `TokenHive.ExecutionReceipt.v1` |
| Policy 哈希 | `TokenHive.Policy.v1` |
| Policy 集合哈希（部署绑定） | `TokenHive.PolicySet.v1` |

---

## 3. JobSpec 字段（`jobs.Spec`）

JobSpec 描述"用某个 Provider 的凭证，向某处发一个什么样的请求"。

| 键 | 字段 | 类型 | 约束 | 说明 |
|---|---|---|---|---|
| 1 | `Version` | uint32 | 必须 = `1`（`jobs.VersionV1`） | 唯一接受的版本 |
| 2 | `JobID` | bytes | **恰好 16 字节** | 每次请求随机生成，回执原样带回 |
| 3 | `Provider` | string | `[a-z0-9_-]`，≤ 64 | 必须已在 TEE 装载的 Policy 中存在，否则 `no policy for provider` |
| 4 | `Method` | string | `GET`/`POST`/`PUT`/`PATCH`/`DELETE` | **不支持 HEAD**（无响应体可证明） |
| 5 | `Host` | string | `host:port`，≤ 253，不含 `/`、`@`、`?` 与空白 | 不接受 scheme / path / userinfo，防止传入外部可控 URL。端口省略时 Policy 按 :443 比对，但实际拨号需要显式端口——无端口的作业只能在拨号阶段以 `failed` 回执收场 |
| 6 | `Path` | string | 以 `/` 开头，≤ 2048，不含 `.` / `..` 段与空白 | 必须为绝对路径 |
| 7 | `Query` | string | ≤ 4096 | **不含前导 `?`**（TEE 拼接时补上） |
| 8 | `Headers` | map[string]string | ≤ 32 项；见 3.1 禁止头 | 调用方可设的业务头 |
| 9 | `BodyHash` | bytes | **恰好 32 字节** | `sha256("TokenHive.RequestBody.v1" ‖ body)`。会话类作业 body 必须为空，即对空串取哈希 |
| 10 | `Nonce` | bytes | 8–64 字节 | 让同一内容的不同作业产生不同 JobSpecHash |
| 11 | `ExpiresAt` | int64 | > 0 | Unix 秒。**`now >= ExpiresAt` 即已失效**（含端点） |
| 12 | `MaxResponseBytes` | uint64 | > 0 | 若作业值超过 Policy 限额，作业被**直接拒绝**（见 7.3 第 9 步），不会静默截断；允许的作业生效值即作业值 |
| 13 | `Stream` | bool | — | 期望流式响应 |
| 14 | `Session` | bool | — | 会话类作业（走 Upgrade）。**body 必须为空**（握手没有载荷） |
| 15 | `Credential` | bytes | 可选（见 7.4） | **canonical CBOR 编码的凭证信封** `Envelope`（X25519 混合加密，密封到 TEE 收件公钥）。由 Provider Agent 加密、Hub 中转密文、随每个作业上报；TEE 解密其中 `Secret{Token, Header, Scheme}` 并注入请求。**不带 Credential 的作业会被拒**（`job carries no credential: provider "…"`）；若该 Provider 的上游无需鉴权，则信封内 `Header` 为空即可（见 7.4） |

### 3.1 TEE 独占的请求头（调用方不得设置）

以下头由 TEE 生成/重建，JobSpec 里出现即被拒绝（`ErrInvalidHeaders: "<name>" is controlled by the TEE`）：

```
authorization, host, content-length, transfer-encoding,
connection, proxy-authorization, te, upgrade
```

原因：凭证注入、请求分帧、连接语义都归 TEE 管；这些头可被用来夹带第二个请求或泄露/篡改凭证。

### 3.2 关于"模型"

TEE **不感知模型**：JobSpec 无模型字段，回执也不含模型。模型→价格的映射由 Hub 侧维护（卖家报价表），因此**回执不能证明"用了哪个模型"**，只能证明"发生了这次字节交换、多少字节、什么完成状态"。若你的业务需要价格审计，请在 Hub 侧留痕。

---

## 4. `POST /v1/execute` 协议

### 4.1 请求

```
POST /v1/execute HTTP/1.1
Content-Type: application/cbor

<canonical CBOR of ExecuteRequest>
```

```cbor
ExecuteRequest = {
  1: Spec   ; jobs.Spec，见第 3 章
  2: Body   ; bytes，TEE 原样发给上游的请求体（必须与 Spec.BodyHash 一致）
}
```

TEE 的校验顺序（与 `tee.Service.Execute` 一致）。**除第 1 步外**，任一步失败 → `event: error` 帧，**不签发回执、不消耗 ProviderSeq**：

1. **HTTP 层**：解码 canonical CBOR。失败时 SSE 尚未开始，直接返回 **HTTP 400** 纯文本（`decode request: ...`），**不会出现 SSE `error` 帧**——调用方须把"非 200"也视为拒绝
2. `SubmitterVerifier`（可选钩子，部署方未启用则跳过）——注意它**最先执行**，先于一切作业校验，而非在 Policy 之后
3. `Spec.ValidateAt(now)`：结构 + 过期
4. `Spec.MatchesBody(body)`：请求体与 BodyHash 不符则拒
5. Policy 授权（第 7 章）
6. 请求体大小 > `Policy.Limits.MaxBodyBytes` 则拒
7. 凭证打开：解密作业携带的 `Credential` 信封（JobSpec 键 15）。缺失 / 打不开 / 密钥 ID 不匹配 / 信封绑定到别的 Provider / `Secret` 非法，均拒；见第 7.4 节与第 14 章
8. 分配 ProviderSeq——唯一的状态变更，放最后，保证被拒作业永不留下序号空洞

### 4.2 响应（`text/event-stream`）

三类帧：

**(a) 数据帧（chunk）**——上游响应体的原始字节切片：

```
data: <line1>\n
data: <line2>\n
\n
```

分帧规则（对接时必须精确实现，否则回执流哈希校验必失败）：

- 一个 chunk 内部若含 `\n`，按行拆成多个 `data:` 行；chunk 结束写**一个空行**；
- `data:` 后**固定一个空格**，读取端**只去掉这一个空格**：前导空格是载荷的一部分，不能多删；
- **尾部空白是载荷**，不得 trim；
- **空 chunk 也要算一次**（心跳/空写计入 ChunkCount 与流哈希），不得跳过。

**(b) 回执帧（终止，成功路径）**：

```
event: receipt
data: <base64( canonical SignedReceipt )>

```

**(c) 错误帧（终止，拒绝路径）**：

```
event: error
data: <原因文本（单行）>

```

> 回执帧与错误帧**必须区分**：错误帧表示 TEE 拒绝或内部失败，**永不伴随回执**。写线上前的拒绝（第 4.1 节第 2–8 步）无回执、无 ProviderSeq 消耗；极少数写线后的内部故障（如 `sign receipt: ...`）会消耗序号却无回执交付——按 ProviderSeq 语义这是"留洞"而非"隐藏"（见第 10.1 节），调用方不应据此计费。把"没有回执帧"和"错误帧"当成一回事会丢掉原因。

### 4.3 调用方必须做的校验

1. 收集所有 chunk（按 4.2 规则还原字节，不 trim）；
2. 解析 `receipt` 帧 → `SignedReceipt`；
3. `proof.Verify(signed, opts)`（第 8 章）；
4. `signed.Receipt.MatchesStream(chunks)`——校验回执的 StreamHash 覆盖的就是你收到的字节。**这一步不能省**：它是"Hub 交给用户的字节 == TEE 见证的字节"的唯一保证。

---

## 5. `GET /v1/session` 协议（长会话）

用于 Realtime 一类需要长连接双向流的场景。TEE 不解析 WebSocket 帧内容，只**搬运、计量、摘要**字节。

### 5.1 握手

1. 客户端发起 WebSocket Upgrade（服务端**不校验 Origin**）；
2. 客户端发送**第一条 Binary 帧** = canonical `SessionRequest`：

```cbor
SessionRequest = {
  1: Spec   ; Spec.Session = true，Body 必须为空
  2: Body   ; 空
}
```

3. TEE 校验（同 4.1）后回复：
   - 成功：Text `{"ok":true}`
   - 失败：Text `{"error":"<原因>"}`（例如 `{"error":"first frame must be binary"}`）

首帧读取超时 **30 秒**；成功握手后该超时解除。

### 5.2 透传

- **上行**：客户端 Binary 帧 → 上游隧道；
- **下行**：上游字节 → 客户端 Binary 帧；
- 非 Binary 帧（ping/pong 等控制帧）由库自行处理，TEE 不转发业务内容。

### 5.3 收尾

上游流结束（干净 EOF）后，TEE 签发**会话回执**，作为**最后一条 Text 消息**发送，然后关闭 WebSocket：

```json
{"receipt":"<base64( canonical SignedReceipt )>"}
```

异常时为 `{"error":"sign session receipt: ..."}`。客户端应把"最后一条 Text 消息"视为会话回执。

### 5.4 会话生命周期

- 会话**没有总时长上限**——只有**空闲**会终止：任意方向**静默超过 5 分钟**（`SessionIdleTimeout`）TEE 拆除会话。空闲计时由任一方向成功转发的字节重置。
- 因此：长时间"安静但存活"的会话不会死；对端消失导致的僵死连接会被回收。

---

## 6. 回执结构（`proof.SignedReceipt`）

```
SignedReceipt = {
  1: Receipt              ; 被签名的执行事实
  2: platform.Signature   ; 由回执内嵌的已证明公钥签发，域 TokenHive.ExecutionReceipt.v1
}
```

### 6.1 `Receipt` 字段

| 键 | 字段 | 说明 |
|---|---|---|
| 1 | Version | 固定 1 |
| 2 | JobID | 原样回显作业的 16 字节 |
| 3 | JobSpecHash | `sha256("TokenHive.JobSpec.v1" ‖ canonical(Spec))` |
| 4 | Provider | 提供者标识 |
| 5 | Method | 实际方法 |
| 6 | Host | 实际主机 |
| 7 | Path | 实际路径 |
| 8 | StatusCode | **上游真实状态码**（401/429/500 都照实签）；会话回执固定为 101（升级成功） |
| 9 | StreamHash | 流式摘要：覆盖所有 chunk 与其顺序 |
| 10 | ChunkCount | chunk 个数（含空 chunk） |
| 11 | ResponseBytes | 响应字节数 |
| 12 | Completion | 1=complete / 2=truncated / 3=failed |
| 13 | StartedAt | Unix 秒 |
| 14 | FinishedAt | Unix 秒（≥ StartedAt） |
| 15 | Attestation | 证明引用（见 6.2），通常内联 |
| 16 | PolicyHash | 本次授权所依据的 Policy 哈希 |
| 17 | RequestBytes | 实际写入上游的请求字节数 |
| 18 | ProviderSeq | **Provider 单调序号**，审计连续性的关键 |

**Completion 语义**：

| 值 | 含义 | 是否计费 |
|---|---|---|
| 1 `complete` | 上游正常结束 | 仅当 StatusCode 为 2xx 时计费；会话回执（101、正常结束）亦计费 |
| 2 `truncated` | 达到 `MaxResponseBytes` 上限，或上游中途断连 | 不计费 |
| 3 `failed` | 请求从未产生可用响应 | 不计费 |

> 失败也会被签发回执——这正是调用方能证明"我没收到该付钱的东西"的依据。

### 6.2 `Attestation`（证明引用）

| 键 | 字段 | 说明 |
|---|---|---|
| 1 | Platform | `simulated`（本地仿真）或 `aws-sev-snp`（AWS SEV-SNP 机密虚拟机） |
| 2 | AttestationType | 证明格式标签；仿真为 `sim-software` |
| 3 | ApplicationID | 飞地镜像标识；仿真为 `tokenhive-sim@v1` |
| 4 | KeyID | 公钥指纹（32 字节） |
| 5 | PublicKeyDER | 已证明的签名公钥 |
| 6 | EvidenceHash | 证明字节的 sha256 |
| 7 | Evidence | 证明字节本身（**可缺省**，见 6.3） |

仿真证据为 JSON，形如：

```json
{
  "version": 1,
  "measurement": "0000…dead",
  "host_data": "tokenhive-simulation",
  "debug": false,
  "policy": "NO_DEBUG,NO_MIGRATE",
  "policy_set_hash": "e488c28b…"
}
```

其中 `policy_set_hash` 是**部署白名单集合的哈希**（第 7.1 节）：它让回执能证明"这个飞地装的就是这份白名单"，而不只是"可信镜像跑过"。

### 6.3 内联证据 vs 证据取回

- 本地仿真默认**内联证据**（`cmd/tee -evidence=true`），回执自包含、可离线验签。
- 生产可关闭内联以压缩回执，此时验证方需按 `EvidenceHash` 从证据服务取回证据。**该证据取回接口属于部署侧待补项**（上线前必须提供），否则关闭内联后回执无法离线验证。

---

## 7. Policy：凭证被允许用在哪

### 7.1 谁定义、如何生效

- Policy 是 **Hub 预定义的白名单**，随 TEE **部署配置**加载（`policy.Set.Install / InstallAll`）。Provider 无需参与签名或轮换。
- 完整性由**证明**背书：TEE 启动时计算整个 Policy 集合的哈希（`policy.Set.Hash()`），并把它绑进 attestation（仿真落在证据的 `policy_set_hash` 字段；真实 SEV-SNP 中 Policy 随镜像/受保护配置一起被 measurement 覆盖）。因此**改动任何一个白名单条目都会改变这个哈希**，验证方可据此判断飞地装的是不是预期那份白名单。

### 7.2 Policy 字段

| 键 | 字段 | 说明 |
|---|---|---|
| 1 | Version | 1 |
| 2 | Provider | 与 JobSpec.Provider 同名规则 |
| 3 | DisplayName | 可选 |
| 4 | Hosts | 允许的上游 `host:port` 列表（≤16） |
| 5 | Rules | 规则列表（≤64）：`{Methods, Path, AllowStream, QueryKeys, AllowAnyQuery}` |
| 7 | Limits | `{MaxResponseBytes, MaxBodyBytes, AllowedHeaders}` |
| 8/9 | IssuedAt / ExpiresAt | 生效窗口 |
| 11 | Nonce | 可选，让相同内容的两份 Policy 产生不同哈希 |

> 键 6（旧 `Credential` 注入形态）、键 10（旧 `ProviderKey` 签名公钥）、键 12（旧 `RateCard` 定价）均已**永久作废**：凭证的形状随 token 密封进每次作业的信封（`Secret{Token, Header, Scheme}`，见第 7.4 节），定价是 Hub 侧报价表（见第 10.2 节），两者都不属于这份分布式白名单。

### 7.3 授权判定与拒绝原因

判定顺序（先到先拒）：

| 顺序 | 检查 | 错误 |
|---|---|---|
| 1 | 该 Provider 有 Policy 吗 | `no policy for provider: "<p>"` |
| 2 | Policy.Provider == Spec.Provider | `policy provider does not match the job` |
| 3 | Host 在白名单 | `host is not allowed by policy: "<h>"` |
| 4 | Path 匹配规则（含 `{占位符}`） | `path is not allowed by policy: "<path>"` |
| 5 | Method 在该规则内 | `method is not allowed by policy: "<M> <path>"` |
| 6 | 调用方 Header 在 `AllowedHeaders` | `header is not allowed by policy: "<h>"` |
| 7 | Query 键允许（`QueryKeys` / `AllowAnyQuery`） | `query parameter is not allowed by policy: "<k>"` |
| 8 | 流式是否被允许 | `streaming is not allowed by policy: "<M> <path>"` |
| 9 | 限额：`min(作业, Policy)` | `job exceeds a policy limit: …` |

凭证由 TEE 从作业携带的信封内解密出 `Secret{Header, Scheme, Token}` 并注入请求（见 7.4）；调用方永远拿不到、也设置不了它——`authorization` 等凭证头在 JobSpec 里出现即被拒（第 3.1 节）。

---

## 7.4 凭证如何到达 TEE（凭证平面与信封）

凭证是**作业携带的**，TEE 不持久化：每个 JobSpec（键 15）带一份 `Envelope`（凭证信封），TEE 在飞地内用私钥解出 `Secret`，注入请求，执行完丢弃。整条链路保证 **Hub 永不接触明文**。

### 7.4.1 `Secret`：凭证的形状

`Secret{Token, Header, Scheme}` 三个字段覆盖所有主流 AI 服务的鉴权形态，Seller 只需填一次：

| 服务 / 形态 | `Header` | `Scheme` | 落网的请求头 |
|---|---|---|---|
| OpenAI 及多数服务 | `authorization` | `Bearer` | `Authorization: Bearer <token>` |
| Anthropic 等 | `x-api-key` | *空* | `x-api-key: <token>` |
| 任意自定义 | 任意头名 | 可选前缀 | `<Header>: <Scheme> <token>`（Scheme 为空则 `Header: token`） |
| 无需鉴权 | *空 Header* | 空 | 什么都不注入（`Token`/`Scheme` 必须也为空，否则非法） |

`Secret` 在每次作业解密后先经 `Validate()`（头名合法性、保留头拒绝、token 无控制字符/首尾空白），不合规即拒、绝不落网。

### 7.4.2 `Envelope`：X25519 混合加密信封

`Envelope{KeyID, Ephemeral, Nonce, Ciphertext}` 是一次性密钥交换的产物（TEE 用 `tee.EncryptCredential` / Agent 用同一函数生成）：

- `KeyID`：收件公钥指纹，TEE 据此拒绝发给旧收件密钥的信封（TEE 重启生成新密钥对，旧信封自然失效，Agent 下次上线自动重封）；
- `Ephemeral` + `Nonce` + `Ciphertext`：一次性 X25519 临时公钥 + AES-GCM 随机 nonce + 密文，密钥由 `ECDH(收件私钥, 临时公钥)` 派生；
- 密文内容是 `{Provider, Secret, IssuedAt}` 的 JSON——**Provider 被绑进密文**，Hub 无法把给 Provider A 的信封改派给 Provider B（TEE 打开后比较声明 Provider 与作业 Provider）。

信封对外有两种形态：控制面上以 **JSON**（`key_id`/`ephemeral`/`nonce`/`ciphertext`，base64）在 Agent 注册时经 Hub 中转；作业面上由 Hub 用 **canonical CBOR** 编码后放进 `JobSpec.Credential`。两条形态编解码都在 `tokenhive/tee`（`EncodeCanonical` / `DecodeEnvelope` / `EncryptCredential`）。

### 7.4.3 凭证生命周期（Agent 上线 → 掉线）

1. **TEE 启动**时生成一对 InboxKey（私钥只在飞地内存，永不落盘；重启即轮换）；
2. **Agent 上线**：拨 Hub 的 AgentGate，先经 Hub 的 `/v1/credential-key` 拉取当前 TEE 公钥，用 `tee.EncryptCredential` 把自己的 `Secret` 密封成 `Envelope`，随注册消息 `AgentRegister` 上报；
3. **Hub** 只把信封（密文）存入自己的**凭证库**（`CredentialStore`，内存或文件），**不在 Hub 内存里出现明文**；
4. **调度时**，Hub 把该 Provider 当前的信封 canonical 编码后放进每次作业的 `JobSpec.Credential`（`execute` 与会话 `/v1/session` 都如此）；
5. **TEE 执行**时用私钥解开信封并注入请求；
6. **Agent 掉线**：Gate 检测到控制流关闭，从凭证库**删除**该 Provider 的信封（撤销注册），之后该 Provider 无凭证可派，作业被 TEE 以 `job carries no credential` 拒绝，而不是用失效/盗用的 token 硬发。

> 安全含义：Hub 全程只见密文信封；即便 Hub 被攻破，它手上也只有打不开的信封。唯一的解密能力在 TEE 私钥，而私钥从不离开飞地内存。一个被攻破的 Hub 能做的极限是"把一个 Provider 的信封随作业转发"，但信封绑定了 Provider 且只对白名单内的 host/path 生效，所以既无法改派、也无法外泄明文。

---

## 8. 验证回执（验签）

```go
import "github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"

err := proof.Verify(signed, proof.VerifyOptions{
    Now:              time.Now(),                 // 验证方时钟；零值用 time.Now()
    AllowedPlatforms: []string{"aws-sev-snp"},    // 只信任这些证明平台；空=不限制
    RequireEvidence:  true,                       // 没有证据取回能力时应置 true，拒绝无内联证据的回执
    MaxAge:           24 * time.Hour,             // 拒绝过老的回执；0=不检查（归档场景）
})
```

`proof.Verify` 检查：结构合法性 →（可选）证据存在 → 平台白名单 → 用回执内嵌的**已证明公钥**验证签名。

> **它不验证证据本身**。把"某个飞地签了"升级为"我信任的飞地签了"，是验证方自己的信任根要做的事：
> - 仿真：`simulated.CheckEvidence(id)` 校验证据格式/非 debug/measurement；`simulated.CheckEvidenceForDeployment(id, policySetHash)` 额外校验部署白名单绑定。
> - 生产（`aws-sev-snp`）：由部署方提供的 RA-TLS 信任根与镜像 measurement 对照（含 `policy_set_hash` 所对应的部署配置）。

**最小验证清单**（缺一项都可能被伪造或漏审）：

1. `proof.Verify` 通过；
2. `MatchesStream(chunks)` ——你收到的字节就是回执见证的字节；
3. `JobSpecHash` == 你自己 canonical 编码的 Spec 的哈希（含 body hash）；
4. `ProviderSeq` 连续（第 10.1 节）；
5. 证据链与你信任的 measurement / 部署白名单哈希一致。

---

## 9. 传输行为与重试语义（TEE → AI 服务商）

| 项 | 行为 |
|---|---|
| 协议 | **HTTP/1.1 only**（ALPN 锁 `http/1.1`）；不支持上游 h2 |
| TLS | ≥ 1.2；生产默认用系统信任根（真实服务商证书链） |
| 连接 | **连接驻留**：按 `(Provider, Host)` 池化复用；空闲连接由后台回收器按 `IdleTimeout` 清理，不再依赖"下次取用时才清理" |
| 一次重拨 | 若请求在一条已死的连接上**一个字节都没写出**，TEE 会**重拨一次**重试（没有东西被花掉两次） |
| 半开连接 | 一旦有字节写入后失败，连接**直接丢弃**，绝不以半开状态放回池里复用 |
| 上游非 2xx | **不算错误**：401/429/500 都会照实签回执（带 StatusCode），供计费与争议解决 |
| 截断 | 超过 `min(作业, Policy)` 的响应上限或上游中途断连 → `completion=truncated` |

对调用方的含义：**不要因为收到 401/429 就认为调用失败**——那是被证明过的上游拒绝，回执本身就是证据。

---

## 10. Provider（卖家）视角

### 10.1 你的 token 被怎么用、你能审什么

- **token 如何被平台使用**：你的 token 由供方侧进程（Provider Agent，见 10.3）或一次性工具用 **TEE 收件公钥加密**后随注册上报；Hub 只持有**密文信封**并在每次作业时转发给 TEE，**Hub 本体从不接触你的明文 token**。TEE 在飞地内解密后才把它注入请求（见 7.4）。
- token 只会被注入到 **Policy 白名单内的 host/path/method**（第 7 章）；平台侧无法让 TEE 拿你的 token 去访问白名单外的接口（例如账户、账单类接口）。
- **Agent 掉线立即撤销**：供方 Agent 与控制流断开时，Hub 从凭证库删除该 Provider 的信封，token 停止被使用（见 7.4.3）。
- 每次使用都会产生一张**签名回执**，含：上游状态码、响应字节数、请求字节数、完成状态、时间、Policy 哈希、**单调序号 ProviderSeq**。
- **审计**：回执按 Provider 分目录存储，可用离线验证工具检查签名与序号连续性：

```bash
verify                        # 校验全部 Provider 的回执 + 报告序号缺口
verify -provider openai-sim   # 只看一个 Provider
```

输出示例：`[openai-sim] GAP: N receipts but missing seq [2] (provider was used at least 3 times)`——**序号出现缺口即说明有执行没有交付回执**，这是平台无法抵赖的信号。

### 10.2 定价

- 定价**不在 Policy 里**（Policy 键 12 已作废）。你的报价以**卖家报价表**形式由 Hub 维护（每请求价、每 MB 价、按模型的加价）。
- 结算：回执是你的收入凭证（完成且 2xx 才计费）；平台抽成单独记账，**不改你的卖价**。

### 10.3 Provider Agent（出口代理）

若你希望 TEE 经**你的网络出口**访问 AI 服务商（例如住宅 IP / 固定出口）：

- **Agent 同时承载两件事**：其一是一条反向隧道让 TEE 经你的网络出口访问上游；其二是把你声明的 `token` 用 TEE 收件公钥加密、随注册上报（7.4.3）。所以**你的 token 只写在你自己的 Agent 启动参数里**，平台上只有密文信封。
- Agent 是你机器上的进程，位于 NAT 后**不可被拨入**：它主动拨 Hub 的 AgentGate 并保持反向隧道，断开自动重连。
- 契约：**多路复用反向隧道**。Agent 主动拨 Hub 的 AgentGate，与 Hub 之间是一条多路复用 WebSocket；Hub 在隧道上为每条流指定一个上游 `host:port`（必须落在 Agent 的 `-targets` allowlist 内），Agent 拨向该 host 并双向复制字节。Agent **不做应用层代理、不解密**——TEE 与 AI 服务商的 TLS 会话端到端加密封装穿过隧道。
- 安全边界：Agent 永不接触 TLS 密钥，只能看到未参与会话的一段密文；可用 tap 把转发字节落盘自证"只见到密文"。
- **认证形状尽量少配**：Agent 启动时默认按 `authorization` 头 + `Bearer` 前缀上报 token（覆盖 OpenAI 及多数服务）；若你的服务用 `x-api-key` 这类"原样 token 头"，只需传 `-auth-header x-api-key`（`-auth-scheme auto` 会自动改为"无前缀"）。需要完全自定义时再显式写 `-auth-scheme`。
- 启动参数要点：`-hub <AgentGate URL>`、`-key <共享密钥>`、`-provider <标识>`、`-token <你的 access token>`、`-targets <允许的 host:port>`、`-auth-header <鉴权头，默认 authorization>`、`-auth-scheme <auto|Bearer|其它|空>`、`-price <微单位/请求，0 表示接受平台默认>`、`-tap <落盘路径>`。

---

## 11. 接入清单（上线前逐项打勾）

- [ ] 用**确定性 CBOR**（整数键、键排序、最短长度、无不定长）编码；Go 方直接用 `tokenhive/tee` 的 `EncodeCanonical`
- [ ] JobID 每次随机 16 字节；Nonce 8–64 字节；ExpiresAt 设置为"现在 + 很短的窗口"
- [ ] BodyHash = `sha256("TokenHive.RequestBody.v1" ‖ body)`，且发送体与之一致
- [ ] 不设置任何 TEE 独占头（`authorization`/`host`/`content-length`/…）
- [ ] SSE 读取严格按分帧规则（保留前导空格、不 trim 尾部、空 chunk 计数）
- [ ] 区分 `receipt` 帧与 `error` 帧；无回执 = 不可结算（拒绝类错误不消耗 ProviderSeq，见 4.2 末注）
- [ ] 验签 + `MatchesStream` + `JobSpecHash` 自算比对
- [ ] 记录每个 Provider 的 `ProviderSeq` 并检查缺口
- [ ] 生产环境：Hub↔TEE 启用 mTLS（部署层），并校验 attestation 的 measurement 与部署白名单哈希
- [ ] 明确：回执**不含模型信息**；若需模型级对账，在 Hub 侧留痕

---

## 12. 相关但不属于 TEE 的接口

**Hub 用户面 API**（终端用户用 OpenAI SDK 直接调）：`POST /v1/chat/completions`、`POST /v1/messages`（Anthropic 格式）、`POST /v1/responses`（OpenAI Responses 格式）。要点：

- Hub 是**字节中继**，不改写上游帧：`/v1/chat/completions` 追加 `data: [DONE]` 终止标记；`/v1/messages` 以 `message_stop` 结束、`/v1/responses` 以 `response.completed` 结束，**不追加 `[DONE]`**。
- 长会话：Hub 另有用户面 WebSocket 端点 **`GET /v1/session`**（模型取自首帧 JSON）。它与 TEE 侧同路径端点（第 5 章）**不是同一个**——前者面向终端用户，后者是 Hub↔TEE 内部面。接入方务必确认打的是 TEE 的 `/v1/session`。
- 请求体中的 `model` 字段决定走哪个 Provider（最低价优先）；身份为 `X-TokenHive-Key` 头（v1 占位，非最终鉴权方案）。
- 调度失败（无 Provider / 配额）在首字节写出前返回 JSON 错误（404/429/502），而非 SSE 错误帧。

---

## 13. 限制与常量速查

| 项 | 值 |
|---|---|
| 支持方法 | GET / POST / PUT / PATCH / DELETE（**无 HEAD**） |
| JobID | 16 字节 |
| BodyHash | 32 字节 |
| Nonce | 8–64 字节 |
| Host 长度 | ≤ 253 |
| Path 长度 | ≤ 2048（绝对路径，无 `.` / `..`） |
| Query 长度 | ≤ 4096（不含 `?`） |
| Headers | ≤ 32 项 |
| Provider 名 | `[a-z0-9_-]`，≤ 64 |
| 响应上限 | `min(作业 MaxResponseBytes, Policy 限额)` |
| 会话空闲超时 | 5 分钟 |
| 会话首帧读超时 | 30 秒 |
| 上游协议 | HTTP/1.1（ALPN 锁定），TLS ≥ 1.2 |
| 证明平台 | `simulated`（仿真）/ `aws-sev-snp`（生产） |
| 回执签名 | ECDSA P-256 SHA-256 ASN.1，域 `TokenHive.ExecutionReceipt.v1` |

## 14. 错误文本速查

**通道说明**：下表各行分属不同通道——`decode request` 在 SSE 开始前以 **HTTP 400** 纯文本返回（见 4.1 第 1 步）；两个会话专有行经 WebSocket **Text 控制消息** `{"error": ...}` 返回（见本表后注）；末行"传输/上游失败"实际**签发回执**而非错误帧；其余各行是 `/v1/execute` 的 SSE `event: error` 帧 data（HTTP 200 下）。拒绝类错误一律**不签发回执、不消耗 ProviderSeq**；唯一例外是执行中内部故障（如 `sign receipt: ...`，SSE error 帧但序号已消耗），见 4.2 末注。

| 文本（前缀） | 含义 | 是否消耗 ProviderSeq |
|---|---|---|
| `decode request: …` | 请求体不是 canonical CBOR（**HTTP 400**，非 SSE） | 否 |
| `unsupported job spec version: …` | Version ≠ 1 | 否 |
| `invalid job ID / nonce / body hash / expiry / limit` | 结构校验失败 | 否 |
| `job spec has expired: …` | 超过 ExpiresAt | 否 |
| `request body does not match the hash committed in the job spec` | 请求体与 BodyHash 不符 | 否 |
| `no policy for provider: "…"` | 该 Provider 未装载 Policy | 否 |
| `host / path / method / header / query … not allowed by policy` | 白名单拒绝 | 否 |
| `streaming is not allowed by policy` | 该规则不允许流式 | 否 |
| `job exceeds a policy limit: …` | 作业 MaxResponseBytes 超过 Policy 限额 | 否 |
| `request body exceeds the policy limit: …` | 请求体超过 Policy 的 MaxBodyBytes（在 Policy 授权之后检查） | 否 |
| `job carries no credential: provider: "…"` | 作业未携带凭证信封（该 Provider 无在线的 Agent / 未注册） | 否 |
| `credential envelope is bound to provider "…", not "…"` | 信封密文里绑定的 Provider 与作业不一致（改派被拒） | 否 |
| `envelope was not encrypted for this inbox key` / `envelope failed to decrypt …` | 信封密钥 ID 或解密失败（发给旧收件密钥 / 被篡改） | 否 |
| `invalid credential secret: …` | 解出的 `Secret` 形状非法（头名/保留头/token 控制字符等） | 否 |
| `submitter rejected: …` | 部署方启用了 `SubmitterVerifier` 并拒绝该提交方 | 否 |
| 会话专有：`streaming session must carry an empty body: got N bytes` | 会话作业带了非空 body | 否 |
| 会话专有：`streaming session must carry an empty body: Spec.Session is false` | 会话端点收到未置 `Session` 的 Spec | 否 |
| 传输/上游失败（连接、TLS、上游异常） | 一旦进入执行（序号已分配）即签发回执而非 error 帧：无字节产出 → `failed`；中途断流 → `truncated` | 是（已消耗，但以回执记账） |

会话首帧解析失败时，TEE 以 Text 控制消息返回，例如 `{"error":"first frame must be binary"}`、`{"error":"decode session request: …"}`；30 秒内未收到首帧则以策略违规关闭连接。

---

*文档以当前代码为准；若与早期设计文档冲突，以本文档为准。改动协议字段（尤其 CBOR 键号）前请先与 TokenHive 团队确认——键号一旦发布即不复用。*
