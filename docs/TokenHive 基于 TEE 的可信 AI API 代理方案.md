# TokenHive 基于 TEE 的可信 AI API 代理方案

## 1. 背景

TokenHive 的目标是构建一个 AI Token / OAuth 额度共享平台。

系统包含三个主要角色：

- **User**：实际发起 AI 请求的用户
- **Hub**：负责请求路由、计费、调度和结算
- **Provider**：提供自己的 AI 账号、OAuth Token 或 API Key

核心目标是：

1. Provider 的 OAuth Token / API Key 不能泄露给 Hub 或 User
2. Hub 不能越权使用 Provider 的凭证（受 Provider Policy 约束，见 §8）
3. Provider 不能篡改请求或伪造 AI Provider 的响应
4. 请求必须从 Provider 的真实网络出口发出
5. 支持 AI API 的 SSE Streaming
6. 尽量接近普通 HTTPS 的性能
7. 每次调用生成公开可验证的轻量 TEE 执行证明，但不引入 zkTLS / MPC Web Proof

经过对 TLSNotary、MPC zkTLS、TEE zkTLS 以及 `reclaimprotocol/reclaim-tee` 的分析，最终推荐采用：

> **TEE 作为可信 TLS Client，Provider Agent 作为透明 TCP Egress。**

同时基于 `reclaim-tee` 进行裁剪和改造。

> **信任模型调整（2026-08-30）**
>
> **User 侧默认信任 Hub**：不再要求 User 对 JobSpec 签名，也不引入本地 sidecar 代理，JobSpec 由 Hub 直接构造并提交。
>
> **Provider 侧的信任假设不变**：Provider 仍然是唯一不信任 Hub 的一方。因此凭证隔离在 TEE、Provider Policy、TEE 签名回执全部保留，只是回执的主要受众从「User 防范 Hub」转为「Provider 审计凭证使用」。详见 §3.2。
>
> **由此产生一个未决项**：JobSpec 不再携带 User 签名后，TEE 如何确认请求来自合法 Hub。标记为**待定**，留到 `tokenhive/tee/` 服务主体设计时决定（候选方案：Hub↔TEE 传输层 mTLS，或改由 Hub 对 JobSpec 签名）。见 §7。

---

# 2. 最终推荐架构

整体架构如下：

```text
                         TokenHive Hub
                              │
                         JobSpec / Body
                              │
                              ▼
                    ┌──────────────────┐
                    │   TokenHive TEE  │
                    │                  │
                    │ OAuth Token      │
                    │ Policy Engine    │
                    │ HTTP Builder     │
                    │ TLS Client       │
                    │ SSE Parser       │
                    └────────┬─────────┘
                             │
                       TLS Ciphertext
                             │
                             ▼
                    ┌──────────────────┐
                    │ Provider Agent   │
                    │                  │
                    │ TCP Relay Only   │
                    │ No TLS Keys      │
                    └────────┬─────────┘
                             │
                       Provider IP
                             │
                             ▼
                         OpenAI /
                     Anthropic / etc.
```

核心特征：

```text
TLS Endpoint = TEE

TCP Source IP = Provider

Per-request Evidence = TEE Signed ExecutionProof
```

Provider Agent 不终止 TLS，只负责转发 TCP 字节流。

---

# 3. 信任模型

## 3.1 TEE

TEE 是系统中的可信执行环境。

TEE 可以访问：

```text
OAuth Token
API Key
HTTP Request
HTTP Response
TLS Traffic Keys
Provider Policy
Proof Signing Key
```

TEE 必须通过：

```text
Remote Attestation
+
Measured Code
+
Reproducible Build
+
Proof Public Key Binding
```

证明自己运行的是 TokenHive 官方认可代码。

---

## 3.2 Hub

Hub 的信任地位分两个视角，这是 2026-08-30 调整的核心：

- **User 视角：可信。** User 用标准 AI SDK 直接访问 Hub，由 Hub 构造 JobSpec，不再要求 User 对 JobSpec 签名。
- **Provider 视角：仍不可信。** Provider 与 Hub 之间不存在信任关系，凭证必须隔离在 TEE 之内，调用范围必须受 Provider Policy 约束。

Hub 可以：

- 调度 Provider
- 构造并提交 JobSpec
- 做计费
- 接收最终 Response
- 转发 ExecutionProof

但 Hub 不能：

- 获得 OAuth Token
- 获得 TLS Key
- 绕过 Provider Policy
- 伪造 OpenAI TLS Response
- 伪造可以通过验证的 ExecutionProof

已移除的限制：

- **修改已签名 JobSpec** —— JobSpec 不再由 User 签名，Hub 本身就是它的构造者。对 Hub 的约束改由 Provider Policy（§8）与 TEE 回执（§17）从 Provider 一侧施加。

换句话说，Hub 与 User 之间退化为普通的客户端—服务端信任关系：User 相信 Hub 如实转述自己的请求与拿到的响应。TEE 的存在意义并不因此削弱——它保障的是 Provider 的凭证安全与审计利益，而 Provider 从未信任过 Hub。

---

## 3.3 Provider Agent

Provider Agent 同样被视为不可信。

它只负责：

```text
TEE
 │
 │ TLS ciphertext
 ▼
Provider Agent
 │
 │ TCP
 ▼
OpenAI
```

Provider Agent 可以：

```text
drop
delay
disconnect
```

但不能：

```text
读取 OAuth
读取 TLS 明文
修改 HTTP Request
修改 HTTP Response
伪造 OpenAI Response
```

因为所有应用层数据都受到 TLS AEAD 完整性保护。

---

# 4. Provider IP 如何保留

这是整个方案最关键的设计之一。

TEE 并不需要直接建立公网 TCP Socket。

Provider Agent 执行：

```go
net.Dial("tcp", "api.openai.com:443")
```

因此 OpenAI 看到的 Source IP 是：

```text
Provider IP
```

但 TLS Handshake 是由 TEE 完成的。

实际数据链路：

```text
TEE
 │
 │ ClientHello
 ▼
Provider Agent
 │
 ▼
OpenAI

OpenAI
 │
 │ ServerHello
 ▼
Provider Agent
 │
 ▼
TEE
```

Provider Agent 只是：

```text
bidirectional byte pipe
```

因此：

```text
网络出口属于 Provider
TLS Session 属于 TEE
```

---

# 5. OAuth / API Key 生命周期

Provider 首次加入 TokenHive 时：

```text
Provider
   │
   │ Remote Attestation
   ▼
TEE
```

Provider 验证：

```text
hardware = expected TEE
app_hash = approved TokenHiveTEE image
debug = disabled
public_key = expected TEE key
```

验证成功后建立安全通道：

```text
Provider
    │
    │ encrypted
    ▼
TEE
```

上传：

```text
OAuth Token
+
Provider Policy
```

例如：

```yaml
provider_id: provider-123

credentials:
  type: oauth
  token: xxx

policy:
  allowed_hosts:
    - api.openai.com

  allowed_paths:
    - /v1/responses

  allowed_methods:
    - POST

  allowed_models:
    - gpt-5.6
    - gpt-5.5
```

OAuth Token 只存在于：

```text
Provider
TEE
OpenAI
```

而不会被：

```text
Hub
User
其他 Provider
```

看到。

---

# 6. 请求流程

## 6.1 Hub 构造 Job

User 用标准 AI SDK 直接调用 Hub（例如 `POST /v1/responses`），Hub 收到标准请求后构造 JobSpec：

```json
{
  "job_id": "job-123",
  "provider_id": "provider-1",
  "host": "api.openai.com",
  "method": "POST",
  "path": "/v1/responses",
  "body_hash": "0x...",
  "nonce": 1024,
  "expires_at": 1780000000
}
```

字段来源：

- `host` / `method` / `path` / `query` —— 来自 User 的原始请求行
- `body_hash` —— 请求体的 SHA-256，用于把 JobSpec 与实际发送的字节绑定
- `job_id` / `nonce` / `expires_at` —— 由 Hub 生成

**JobSpec 不带 User 签名。** 按 §3.2 的信任模型，User 侧默认信任 Hub，因此这一步没有签名动作，也不需要本地 sidecar 代理。`nonce` 与 `expires_at` 的作用从「防 Hub 重放」降级为「防网络重放与请求错配」，派单幂等由 Hub 自己保证。

JobSpec 的字段校验规则（保留头、host/path 合法性、长度约束）见 `tokenhive/jobs/`。

---

# 7. Hub 转发请求

Hub 向 TEE 提交：

```text
JobSpec
+
Request Body
```

TEE 侧执行两类校验：

```text
SHA256(body) == JobSpec.body_hash
```

以及 JobSpec 自身的结构校验（保留头、host / path 合法性、nonce 与 expiry），由 `tokenhive/jobs/` 完成。

`body_hash` 在这里防的不是 Hub——Hub 就是构造者——而是**防止 JobSpec 与 body 错配**：并发请求之间张冠李戴，或传输过程中的截断与串扰，都会被这一步拦下。

### 已定：TEE 如何识别合法 Hub —— 传输层 mTLS

移除 User 签名后，TEE 失去了一个应用级的请求来源证明。**结论：第一版采用传输层 mTLS，不做应用级的 Hub 签名。**

两个候选方案：

- **传输层 mTLS**（选定）—— Hub 与 TEE 之间建立 mTLS 通道，靠客户端证书识别 Hub。天然挡住外部第三方直接调 TEE，且不引入密钥注册表。
- **Hub 签 JobSpec**（暂缓）—— 由 Hub 对 JobSpec 签名。多一道应用级校验，回执里可记录「是哪个 Hub 派的单」，代价是要维护一套 Hub 公钥注册与吊销。

**选定 mTLS 的论证**，来自本方案此前已经作出的两个决定：

1. 回执的主要受众是 **Provider 与审计方**（§17），不再是 User。
2. Provider 关心的唯一问题是「我的凭证有没有被越权使用」，而这由 **Policy 检查（§8）+ 回执签名（§17）** 完整保证——两者都不依赖请求来自哪个 Hub。

也就是说，**Hub 身份对 Provider 一侧的安全保证贡献为零**。既然如此，为应用级 Hub 签名维护一整套公钥注册，买到的是审计便利（「这笔单是哪个 Hub 派的」），而不是安全性。那属于审计需求，应当在出现明确审计诉求时再做，不应默认背在系统上。

`tokenhive/tee.Config.SubmitterVerifier` 为此预留了插槽：默认留空（依赖传输层 mTLS），需要应用级 Hub 身份时挂上一个校验函数即可，不必改动 `Execute` 的形状。若将来启用，它是一套**新的提交者语义**（含 Hub 公钥注册与吊销），而非 User 签名的复用——后者已于 2026-08-30 从代码中移除。

> 无论最终选哪个，TEE 对 **Provider** 一侧的保证都不受影响：Policy 检查（§8）与回执签名（§17）都不依赖请求来自哪个 Hub。

---

# 8. TEE Policy Check

TEE 在请求发送前执行：

```text
JobSpec
   │
   ▼
Provider Policy
```

检查：

```text
host allowed?
path allowed?
method allowed?
model allowed?
body size allowed?
```

全部通过之后才允许注入：

```text
Authorization: Bearer <OAuth>
```

这样可以防止 Hub 越权利用 Provider Token 调用未授权接口。

> 这是 Hub 可信模型下**唯一剩下的、且不可省略的 Hub 约束**。User 侧信任 Hub 不意味着 Provider 也要信任 Hub：凭证虽然只有 TEE 能碰，但如果不限制调用面，Hub 仍可借 Provider 的 token 去打 `GET /account` 或 `POST /billing`。Policy 是 Provider 划的红线，由 Provider 自己签名（见 `tokenhive/policy/`），Hub 无法绕过。

例如禁止：

```text
GET /account
POST /billing
DELETE ...
```

只允许：

```text
POST /v1/responses
```

---

# 9. HTTP Request 构造

Hub 提交：

```text
POST /v1/responses

Content-Type: application/json

{...}
```

TEE 内部加入：

```text
Authorization: Bearer PROVIDER_SECRET
```

最终：

```http
POST /v1/responses HTTP/1.1
Host: api.openai.com
Authorization: Bearer xxx
Content-Type: application/json
Content-Length: ...

{...}
```

完整 Request 只在 TEE 内部形成。

随后 TEE 使用 TLS 加密。

---

# 10. TLS 链路

最终实际链路：

```text
TEE
 │
 │ encrypted TLS records
 ▼
Provider Agent
 │
 │ raw TCP
 ▼
OpenAI
```

OpenAI Response：

```text
OpenAI
 │
 │ TLS ciphertext
 ▼
Provider Agent
 │
 │ raw TCP
 ▼
TEE
```

TEE：

```text
TLS authentication
+
AEAD integrity verify
+
decrypt
```

因此 Provider Agent 无法伪造响应。

如果篡改任何 TLS ciphertext：

```text
ciphertext byte modified
```

TEE 会得到：

```text
AEAD authentication failure
```

---

# 11. 防止 Provider Redirect / MITM

Provider Agent 可能尝试：

```text
api.openai.com
      ↓
evil-server.com
```

但是 TLS Handshake 在 TEE 内完成。

TEE 会验证：

```text
certificate chain
hostname
SNI
signature
validity
```

因此：

```text
evil-server.com certificate
```

无法通过：

```text
api.openai.com
```

的 TLS 验证。

---

# 12. SSE Streaming

AI API 大部分使用：

```text
Server-Sent Events
```

例如：

```text
data: chunk1

data: chunk2

data: chunk3
```

目标架构必须做到：

```text
OpenAI
   │
TLS record
   ▼
Provider
   │
ciphertext
   ▼
TEE
   │
decrypt
   ▼
Hub
   │
SSE
   ▼
User
```

每个 Chunk 应立即向上传递，同时在 TEE 内增量更新响应摘要：

```text
decrypt chunk
      │
      ├── immediately forward chunk
      │
      └── update SHA-256(response bytes)
```

响应结束后，TEE 对最终摘要和 Job 元数据签名并返回证明：

```text
last chunk
    ↓
finalize response_hash
    ↓
sign ExecutionReceipt
    ↓
return ExecutionProof
```

因此证明生成不阻塞首字节或中间 Chunk。只有最终证明需要等待响应结束，User 可以在消费 SSE 的同时增量计算相同摘要，并在流结束时验证。

---

# 13. TLS Connection Reuse

`reclaim-tee` 当前 HTTP Provider 使用：

```http
Connection: close
```

这是为了 Web Proof 简化 session boundary。

但 TokenHive 不应该这样做。

推荐：

```text
HTTP/1.1 Keep-Alive
+
TLS Connection Pool
```

例如：

```text
Provider A
api.openai.com

connection #1 → SSE request A
connection #2 → SSE request B
connection #3 → idle
connection #4 → idle
```

当：

```text
request A finished
```

则：

```text
connection #1
      ↓
return to pool
```

下一次请求直接复用。

---

# 14. SSE 与 HTTP/1.1 的并发

一个 HTTP/1.1 SSE Response 没结束之前，该连接不能同时执行其他普通请求。

因此不能：

```text
one TLS connection

├─ SSE A
├─ SSE B
└─ SSE C
```

并发。

正确方案是：

```text
TLS Connection Pool

conn-1 → SSE A
conn-2 → SSE B
conn-3 → SSE C
conn-4 → idle
```

这已经可以满足第一版生产需求。

---

# 15. HTTP/2

第一版不建议实现 HTTP/2。

直接使用：

```text
TLS 1.3
+
HTTP/1.1
+
Keep Alive
+
Connection Pool
+
SSE
```

已经足够。

HTTP/2 可以作为后续优化：

```text
one TLS connection

stream 1 → Job A
stream 3 → Job B
stream 5 → Job C
```

但会显著增加：

```text
framing
flow control
stream state
HPACK
multiplexing
```

复杂度。

---

# 16. 为什么不需要 MPC

原 reclaim-tee 使用：

```text
TEE_K
  │
  │ MPC
  ▼
TEE_T
```

主要目的是防止单个 TEE 同时看到完整：

```text
request
+
response
```

这是 Web Proof 场景的隐私设计。

TokenHive 的需求不同。

我们允许：

```text
TEE knows OAuth
TEE knows request
TEE knows response
```

只要求：

```text
Hub cannot know OAuth
User cannot know OAuth
Provider Agent cannot know TLS plaintext
```

因此不需要：

```text
TEE_K
+
TEE_T
+
MPC
```

可以直接：

```text
Single TEE
```

终止 TLS。

---

# 17. 轻量 TEE Proof，而不是 ZK Proof

TokenHive 需要为每次调用生成可公开验证的执行证明，但验证者可以信任通过 Remote Attestation 认可的 TEE 代码，因此不需要用 ZK 电路重新证明完整 TLS 计算。

TEE 为每个 Job 生成：

```text
ExecutionProof
├── receipt
│   ├── version
│   ├── job_id
│   ├── nonce
│   ├── job_spec_hash
│   ├── response_hash
│   ├── response_status
│   ├── completion_state
│   ├── hash_scope
│   ├── provider_id
│   ├── target_host
│   ├── started_at
│   ├── completed_at
│   ├── tee_key_id
│   └── attestation_id
├── tee_signature
└── attestation_evidence | attestation_reference
```

其中：

- `job_spec_hash` 是 Hub 提交的 canonical JobSpec 摘要，不包含 OAuth Token / API Key
- `response_hash` 是 TEE 从目标 TLS Session 解密后、向上游转发的确定性响应字节摘要
- `tee_signature` 使用专用证明密钥签名，并使用 domain separation，避免与 TLS 或其他签名协议混用
- `receipt` 必须采用确定性编码后再签名，例如 RFC 8949 Deterministic CBOR；不能直接签名字段顺序不稳定的普通 JSON
- 证明公钥必须绑定进 Remote Attestation；验证者同时检查代码度量、证明公钥、证据有效期和撤销状态
- `job_id + nonce` 必须来自 Hub 提交的 JobSpec，并进入回执签名，防止旧证明被替换或重放到新 Job
- 大体积 Attestation Evidence 可以按 `attestation_id = SHA-256(evidence)` 缓存和复用，不必附在每个响应中；证据存储必须不可变且可供验证者取回

`response_hash` 必须规定唯一的字节级契约，例如：

```text
response_hash = SHA-256(
  "TokenHive.Response.v1" ||
  job_id ||
  exact_forwarded_response_body_bytes
)
```

第一版建议只覆盖 TEE 实际向上游发送的 Body/SSE 原始字节，不允许 Hub 重新序列化 SSE 之后再要求验证。HTTP Status 和必要 Header 作为 canonical receipt fields 单独签名。后续若要覆盖完整 HTTP Response，应先定义稳定的 canonical encoding。

验证者拿到响应后自行计算 `response_hash`，再验证 TEE 签名和 Remote Attestation。这样可以检测响应在转述过程中被替换、删改或重排——对 Provider 和审计方而言，这是唯一不依赖 Hub 自述的记录。

对于正常结束、上游错误、取消和中途断流，回执都应签入明确的 `completion_state` 与当前 `response_hash`。Hub 可以丢弃响应或证明，但无法伪造一份验证通过的成功证明；TEE Proof 提供完整性和来源认证，不提供可用性保证。

这个证明准确表达的是：

> 被认可的 TokenHive TEE 接受了指定 JobSpec，并通过其验证过的目标 TLS 连接收到了与 `response_hash` 一致的响应。

它不证明 AI 模型内部如何生成内容，也不能仅凭该证明独立证明 Provider 的公网出口 IP。后者仍依赖 Provider Agent 调度、网络观测或额外的网络出口证明。

### 回执的受众

User 侧默认信任 Hub 之后，回执的主要受众从 User 转为 **Provider 与审计方**：

- **Provider** —— 凭 `PolicyHash` 与 `job_spec_hash` 核对凭证的实际使用是否越界。这是 Provider 唯一能拿到的、不依赖 Hub 自述的执行记录，也是 Hub 可信模型下 TEE 回执仍然必须存在的理由。
- **Hub** —— 用 `completion_state` 决定该不该计费：中途断流的响应不该按完整响应收费。
- **User** —— 不再需要验证回执，User 信任 Hub 转述的响应。若日后重新启用 User 签名，这一层可以再打开。

因此可以删除旧流程中的：

```text
ZK circuits
Selective Disclosure Proof
OPRF
MPC OPRF
Attestor Claim
Legacy Verification Bundle
```

但必须保留并新增：

```text
Remote Attestation
+
TEE-bound Proof Signing Key
+
Streaming Response Hash
+
Signed Execution Receipt
```

---

# 18. 性能模型

删除 MPC / ZK 后，Hot Path 基本只剩：

```text
network IO
+
TLS AEAD
+
HTTP parsing
+
Policy check
+
streaming response hash
```

即：

```text
User
 ↓
Hub
 ↓
TEE
 ↓
Provider
 ↓
OpenAI
```

与普通 HTTPS 相比主要增加：

```text
Hub → TEE network hop
TEE → Provider relay hop
```

密码学本身基本就是普通 TLS 加密和流式摘要：

```text
AES-GCM
or
ChaCha20-Poly1305
+
SHA-256 streaming hash
```

每个 Job 结束时再增加一次 TEE 签名。摘要计算与网络流同步进行，只需要常量级状态，不需要缓存完整 Response；一次签名也不进入 SSE Chunk 的转发路径。

轻量证明的复杂度为：

```text
time    = O(response_bytes) streaming hash + O(1) signature
memory  = O(1) hash state
network = O(1) receipt + signature + attestation reference
extra synchronous RTT = 0
```

第一阶段可以采用以下工程验收目标：

```text
TTFT overhead from proof path       < 1%
streaming throughput overhead       < 3%
final receipt generation p95        < 5 ms
proof size with attestation ref      < 2 KiB
```

这些是需要压测验证的目标值，不是当前实现已经达到的结果。

因此理想情况下性能可以接近：

```text
normal HTTPS × 1.02 ~ 1.10
```

这是工程目标，不是 reclaim-tee 官方 Benchmark。必须通过基准测试分别测量网络转发、摘要计算和最终签名的成本，不能仅由理论复杂度推断生产性能。

实际影响主要取决于：

```text
TEE ↔ Provider RTT
Hub ↔ TEE RTT
Connection reuse
SSE buffer strategy
```

---

# 19. Remote Attestation 不进入每请求 Hot Path

Remote Attestation 只需要发生在：

```text
TEE startup
Provider credential provisioning
TEE version upgrade
TEE reconnect
before current attestation expires
```

例如：

```text
RA
 ↓
bind proof public key
 ↓
cache attestation evidence
 ↓
Requests × 10000 → hash + one receipt signature per request
```

而不是：

```text
Request 1 → RA
Request 2 → RA
Request 3 → RA
```

所以 RA 不需要跟随每个请求同步生成。后台应在当前证据到期前轮换证明密钥和 Attestation Evidence；每个请求仍生成独立 `ExecutionProof`，但复用当前有效证据，证明中携带 `attestation_id` 或证据摘要即可。

如果要求多年后仍能证明回执是在证据有效期内产生，应异步把 `SHA-256(ExecutionProof)` 写入可信时间戳服务或 append-only transparency log。这个锚定不应阻塞 SSE 返回，也不属于第一版每请求 Hot Path。

---

# 20. reclaim-tee 的复用价值

`reclaim-tee` 当前已经实现大量非常有价值的基础设施。

推荐复用：

```text
reclaim-tee
│
├── minitls/
│   ├── TLS 1.2
│   ├── TLS 1.3
│   ├── AEAD
│   ├── certificate verification
│   └── hostname verification
│
├── shared/
│   ├── Remote Attestation
│   ├── RA-TLS
│   ├── image measurement
│   └── logging / common structures
│
├── client/
│   ├── TCP relay
│   ├── network bridge
│   └── proxy support
│
├── providers/
│   ├── HTTP parsing
│   └── secret headers
│
└── deployment/
    ├── Confidential VM
    └── reproducible builds
```

---

# 21. reclaim-tee 当前最重要的现成功能

当前 Reclaim Client 已经实现：

```text
Client
 │
 │ TCP Dial
 ▼
Target Website
```

随后：

```text
TEE_K
 │
 │ TLS bytes
 ▼
Client
 │
 │ TCP
 ▼
Target Website
```

这意味着：

```text
Client = Provider Agent
```

时：

```text
Target Server sees Provider IP
```

这一点与 TokenHive 的需求天然一致。

因此最难的：

```text
TEE terminates TLS
while
Provider owns network egress
```

已经有实现基础。

---

# 22. reclaim-tee 建议删除和替换的部分

对于 TokenHive：

```text
tee_t/                     DELETE
mpc/                       DELETE
oprfmpc/                   DELETE
ZK Proof                   DELETE
Attestor Claim             DELETE
Redaction Proof            DELETE
Legacy Verification Bundle DELETE
```

旧的 Proof Pipeline 替换为：

```text
Streaming Hash
      +
TEE Signed ExecutionReceipt
      +
Cached Remote Attestation Evidence
```

最终：

```text
TEE_K
```

可以直接演化成：

```text
TokenHive TEE
```

---

# 23. 建议新增模块

推荐增加：

```text
token/
├── provisioning
├── credential storage
└── rotation

policy/
├── host policy
├── method policy
├── path policy
├── model policy
└── quota policy

jobs/
├── JobSpec
├── body hash binding
├── nonce
├── expiry
└── signature verification（可选，见 §7）

transport/
├── TLS connection pool
├── TCP relay
├── SSE streaming
└── timeout / retry

provider/
├── Provider Agent
├── network health
├── TCP dial
└── session management

proof/
├── receipt schema
├── streaming hasher
├── TEE signer
├── attestation reference
└── verifier
```

---

# 24. 建议代码结构

可以将 fork 后的项目逐步整理为：

```text
tokenhive-tee/
│
├── cmd/
│
├── tee/
│   ├── server.go
│   ├── session.go
│   ├── credential.go
│   └── policy.go
│
├── tls/
│   └── based on reclaim minitls
│
├── provider/
│   ├── agent.go
│   ├── tcp.go
│   └── tunnel.go
│
├── http/
│   ├── request.go
│   ├── response.go
│   └── sse.go
│
├── jobs/
│   ├── spec.go
│   └── verify.go
│
├── proof/
│   ├── receipt.go
│   ├── hasher.go
│   ├── signer.go
│   ├── bundle.go
│   └── verify.go
│
├── attestation/
│   ├── evidence.go
│   └── key_binding.go
│
└── shared/
```

---

# 25. 第一阶段实现范围

第一版只实现：

```text
OpenAI
+
HTTP/1.1
+
TLS 1.3
+
SSE
+
Provider TCP Egress
+
TEE OAuth Vault
+
Provider Policy
+
TEE Signed ExecutionProof
```

暂时不要做：

```text
HTTP/2
ZK
MPC
Multi-cloud TEE
复杂选择性披露
第三方 Attestor Claim
```

目标是快速验证完整链路。

---

# 26. 第二阶段

增加：

```text
TLS Connection Pool
OAuth refresh
Token rotation
Provider health
request cancellation
retry
quota enforcement
metrics
```

同时做：

```text
TTFT benchmark
throughput benchmark
memory benchmark
connection reuse benchmark
proof generation benchmark
proof verification benchmark
```

---

# 27. 第三阶段

再考虑：

```text
HTTP/2
multi-provider routing
multi-region TEE
TEE failover
credential migration
more AI providers
```

例如：

```text
OpenAI
Anthropic
Gemini
xAI
```

---

# 28. License 风险

目前 `reclaim-tee` GitHub Repository 虽然公开，但未明确看到标准开源 License。

需要注意：

```text
public source code
≠
automatically permitted commercial use
```

因此正式 Fork 并用于 TokenHive 商业产品之前，需要确认：

```text
License
commercial use permission
modification permission
redistribution permission
```

最好直接向 Reclaim Protocol 团队确认。

---

# 29. 最终推荐方案总结

最终架构可以概括为：

```text
                  TokenHive Hub
                        │
                  JobSpec / Body
                        │
                        ▼
                ┌──────────────┐
                │ TokenHiveTEE │
                │              │
                │ OAuth Vault  │
                │ Policy       │
                │ HTTP         │
                │ TLS 1.3      │
                └──────┬───────┘
                       │
                 TLS Ciphertext
                       │
                       ▼
               ┌───────────────┐
               │Provider Agent │
               │               │
               │ TCP Relay     │
               └──────┬────────┘
                      │
                 Provider IP
                      │
                      ▼
                    OpenAI

User ◄──── Response Stream + ExecutionProof ◄──── Hub ◄──── TokenHiveTEE
```

其中：

```text
Hub:
不知道 OAuth

User:
不知道 OAuth

Provider Agent:
不知道 TLS plaintext

TEE:
知道 OAuth + Request + Response

OpenAI:
看到真实 Provider IP
```

同时：

```text
Hub 无法接触 OAuth Token 与 TLS Key
Provider 无法篡改请求
Provider 无法伪造 Response
Provider 无法把连接 MITM 到其他 Server
Provider 可凭回执审计凭证的实际使用是否越界
```

通过：

```text
Hub 通道认证（待定，见 §7）
+
JobSpec 绑定（body_hash）
+
TEE Policy
+
TLS Certificate Verification
+
TLS AEAD Integrity
+
Remote Attestation
+
TEE Signed ExecutionProof
```

共同保证。

---

# 30. 最终结论

`reclaim-tee` 不适合原样作为 TokenHive 的运行系统。

但它非常适合作为：

> **TokenHive TEE 网络层和 TLS 层的代码基础。**

推荐路线：

```text
fork reclaim-tee
      │
      ▼
保留 TLS / RA / Client TCP Relay
      │
      ▼
删除 TEE_T / MPC / ZK / Legacy Proof
      │
      ▼
增加 OAuth Vault + Policy
      │
      ▼
增加 Streaming Hash + TEE Signed ExecutionProof
      │
      ▼
增加 HTTP Keep-Alive
      │
      ▼
增加 TLS Connection Pool
      │
      ▼
增加 SSE Streaming
      │
      ▼
TokenHive Trusted TLS Proxy
```

从当前调研结果来看，这是 TokenHive 在：

```text
安全性
性能
Provider IP 保留
实现复杂度
现有代码复用
```

几个维度之间相对最平衡的方案。
