# TokenHive 改造计划：连接驻留 TEE 与本地全栈仿真

日期：2026-09-03
状态：计划稿（未实施）

定位：本文件修订此前各计划文档中关于「TEE 连接生命周期」与「Hub↔TEE 数据面」的全部表述。既有定案中与连接无关的部分——回执体系与 CBOR 键号、Provider Policy 与定价权、SOCKS5 Agent、仿真平台适配器、三层测试法——继续有效并直接复用，本文件不重复其内容，只在第 10 节给出保留与修订的完整清单。

---

## 0. 设计修订：连接驻留 TEE

此前一版需求设想：TEE 只负责完成与上游 AI 服务商（例如 OpenAI）的 TLS（Transport Layer Security，传输层安全协议）握手，之后把包括 WebSocket 在内的全部网络交互交给 Hub，以此把 TEE（Trusted Execution Environment，可信执行环境）的性能消耗压到最低。这条路线有一个无法回避的代价：握手结束后的记录层加解密若由 Hub 完成，TLS 会话密钥就必须从 TEE 搬运到 Hub。密钥一旦离开 TEE，Hub 就能读写链路上的全部明文——而 TokenHive 信任模型的基石恰恰是「Provider 不信任 Hub，凭证与密钥只存在于 TEE」。把记录层密钥交给 Hub 等于亲手拆掉这块基石：凭证注入、Policy 校验、回执签名共同建立的 Provider 侧保证全部失效，因为持有密钥的一方随时可以绕开这一切。

修订后的定案是：

> **TEE 通过 Provider Agent 发起并全程持有到上游服务商的 TCP 连接与 TLS 会话；用户连续调用的整个过程中这条连接一直保持；Hub 永不持有这条连接，也永不接触任何 TLS 密钥。**

Hub 在数据面上的角色由此收敛为 TEE 的中继：把用户请求交给 TEE，取回 TEE 解密后的响应字节，再分发给用户。

这个修订付出的代价是 TEE 从「只做握手」变为「承担全部记录层加解密」。评估这个代价：TLS 记录层是对称密码（AES-GCM 或 ChaCha20-Poly1305），在现代 CPU 的硬件指令加持下，单字节开销远低于一次内存拷贝，更远低于网络转发本身；既有基准（S5）已实测更昂贵的非对称操作——回执签名——的 p95 只有 0.16 毫秒，记录层开销还要低一个量级。用「TEE 常驻数据面」换「密钥不出 TEE」，买到的是信任模型完整，付出的是可忽略的计算开销。这笔交换是本计划的出发点。

术语约定（首次出现时给出全称，后文直接使用缩写）：TEE 即可信执行环境；TLS 即传输层安全协议；SSE（Server-Sent Events）即服务器推送事件流；SOCKS5 为一种通用 TCP 代理协议；CBOR（Concise Binary Object Representation）为确定性二进制编码（RFC 8949）；ALPN（Application-Layer Protocol Negotiation）为 TLS 的应用层协议协商扩展；mTLS 为双向认证的 TLS。

---

## 1. 修订后的架构总览

```text
User ──HTTP/SSE 或 WS──► Hub ──请求模式：POST /v1/execute + SSE──► TEE ─┐
                             ──流模式：WS 双向通道───────────────► TEE ─┤
                                                                      │ TLS 记录层
                                                                      ▼
                                                            Provider Agent（SOCKS5）
                                                                      │ TCP 密文
                                                                      ▼
                                                            上游 AI 服务商（OpenAI）
```

连接的归属是本图的关键。TEE 到上游的 TCP 连接（经 Provider Agent 隧道）与 TLS 会话由 TEE 独占持有、跨请求长存；Hub 与 TEE 之间是普通的应用通道（承载明文业务数据，生产环境启用 mTLS）；Hub 侧不存在任何到上游服务商或到 Provider Agent 的连接。上游服务商看到的源 IP 是 Provider Agent 的出口地址——这是产品成立的根本，也是 Agent 唯一的存在理由。

数据面的两条腿分工如下。请求模式承载 HTTP 请求—响应型 API（如 /v1/chat/completions 的 SSE 流式补全），线格式沿用现状并冻结；流模式承载 WebSocket 型上游（如 Realtime 类全双工会话），是本次新增的部分。两种模式共享同一套校验、授权、凭证注入、回执机制，差别只在连接上的字节组织方式。

---

## 2. 信任模型与职责分界（连接驻留版）

先重申谁能看到什么，修订只影响一处。TEE 可见：OAuth 凭证、TLS 密钥、请求与响应明文、Provider Policy；不可见：用户的真实身份与账务信息（JobSpec 里的 TenantRef 只是不透明引用）。Hub 可见：请求与响应明文（计费与 usage 解析需要）；不可见：凭证与任何 TLS 密钥——修订后这条禁令从「不接触凭证」加强为「连记录层密钥也不接触」。Provider Agent 可见：只有 TCP 密文；SOCKS5 握手会暴露目标地址，这属必然且无害——它必须拨号才能转发；不可见：任何明文。上游服务商可见：Provider 的出口 IP。

职责分界在既有「字节层归 TEE、语义层归 Hub」原则下微调。TEE 负责：Policy 白名单判定、凭证注入、JobSpec 结构校验与 body_hash 绑定、TLS 记录层、HTTP/1.1 请求序列化与响应分帧读取、流式摘要与回执签名、ProviderSeq 单调序号，以及**连接（Channel）生命周期管理**。Hub 负责：用户面 API、模型到 Provider 的最低价调度、配额、计价与抽成、账本、回执审计、usage（token 用量）解析、重试与故障切换。Provider Agent 负责纯 TCP 字节转发，现状即终态，本计划不改动它。

有一处职责从隐式升为显式：连接生命周期。现状里 TEE 通过标准库 HTTP 客户端的内部连接池实现 Keep-Alive（空闲 90 秒，每 host 上限 16 条），连接复用是实现细节，系统无法观察、声明或断言「连接正在保持」。修订后连接成为系统的一等对象，由 TEE 显式持有、显式回收、显式断言。这是本计划最主要的结构性改动，其余改动都是它的配套。

---

## 3. 核心抽象：Channel（连接驻留的实现）

### 3.1 形态与生命周期

Channel 是一条从 TEE 出发、经某个 Provider 的 Agent、终结于某个上游 host 的 TLS 连接，附带完整的生命周期状态。Channel 管理器按 (provider, host) 二元组组织池，规则如下。

获取。需要执行任务时向管理器索取：池中有空闲 Channel 则复用；没有则经该 Provider 的 Agent 发起 SOCKS5 CONNECT，在隧道之上完成 TLS 握手，新建一条 Channel。

复用与保持。HTTP/1.1 Keep-Alive 语义下，一条 Channel 同一时刻只承载一个在途请求（HTTP/1.1 的串行约束）；响应体读到 EOF 后 Channel 回到空闲态。空闲 Channel 在配置的窗口内（默认数分钟）不主动关闭，期间用户再次调用继续复用同一条连接——「用户调用过程中连接一直保持」由这条规则落实。并发请求超出单连接串行能力时，管理器为同一 (provider, host) 增开新 Channel，池有上限。

作废。任何异常——响应中途断流、读错误、超时、Agent 断开——之后连接状态不可信，Channel 整体作废关闭，绝不复用半开连接；下一次请求重新拨号。TLS 会话票据缓存（标准库 ClientSessionCache）让重拨的握手成本压缩到一次往返。

隔离。Channel 与 Provider 严格绑定：两个 Provider 即使访问同一 host，也各自走各自的 Agent、各自的连接。上游看到的源 IP 必须是本次任务所属 Provider 的出口，这一点不因连接复用而稀释。

### 3.2 数据面实现：为什么放弃标准库 HTTP 客户端

标准库客户端的连接池不可观测、不可控：没有「这条连接属于哪个 Provider」的概念，空闲超时语义固定，无法把连接当成显式对象管理；而且它的自动行为（透明 gzip 解压、静默重试、跟随重定向、环境变量代理）此前已被逐一显式关闭以保住回执契约。连接驻留要求连接是一等对象，因此数据面改为手工实现，且刻意把自写部分压到最小：

请求侧完全手工序列化 HTTP/1.1——请求行、JobSpec 允许的头、注入的凭证头、Host 与 Content-Length，除此之外一个字节都不多（没有自动行为恰是优点），经 TLS 连接写出。响应侧交给标准库的 http.ReadResponse 在同一条连接上解析——Content-Length 与 chunked 分帧由标准库消化，body 以字节流形式交给既有的 relay 回调与流式哈希器（StreamingHasher），与现状的数据流完全一致。bufio.Reader 持久挂在 Channel 上跨请求复用，避免丢弃预读字节；WebSocket 升级成功后，缓冲区里的残余字节作为首段下行数据并入透传管道。

TLS 配置沿用标准 crypto/tls（此前已定案不基于 minitls），ALPN 只提供 http/1.1，协商结果确定。HTTP/2 明确不支持——锁死 1.1 是显式连接模型的前提（h2 的多路复用会模糊「一条连接承载一个在途请求」的边界），且主流 AI API 均兼容 1.1；h2 留待后续阶段，与既有文档的判断一致。

### 3.3 接口与改造路径

```go
// tokenhive/transport：新增 channel.go，取代 http.go；socks5.go 原样保留
type ChannelManager struct { /* per-(provider,host) 池、拨号器、TLS 配置、空闲窗口 */ }

// ChannelManager 满足既有 tee.Transport 接口，Do 签名不变
func (m *ChannelManager) Do(ctx context.Context, req tee.Request,
    onChunk func(chunk []byte) error) (tee.Response, error)
```

tee.Service 的主体流程（校验 → 授权 → 注入 → 执行 → 摘要 → 签回执）与 /v1/execute 线格式全部不动；改动的只是 tee.Transport 的实现从「net/http 包装」换成「ChannelManager」。这是刻意选择的改造路径：把结构性改动压缩在一个包内，接口（tee.Transport）两侧的代码与测试全部保值——包括 tee.Service 的全部单测、faketee（其 Transport 本来就是脚本化的内存实现，不受影响）、以及 Hub 侧完全不知道连接的存在。

---

## 4. Provider 注册表：Agent 地址的分发

产品事实是：Provider 把自己 Agent 的 IP 地址告诉 Hub，Hub 是路由信息的事实源；而 TEE 拨号时必须知道「Provider P 的出口是 Agent 地址 A（可能附带 SOCKS5 的 RFC 1929 用户名口令）」。设计上在 TEE 侧新增一个 ProviderRegistry：一个窄接口加两个实现——内存实现供生产、文件实现供仿真。生产路径下由 Hub 通过管理端点把 provider 到 Agent 的映射装载进 TEE（Hub 是事实源，TEE 是使用方）；仿真路径下由启动配置直接写入。

JobSpec 不携带 Agent 地址。理由：JobSpec 的语义是「凭证使用授权」，其哈希（job_spec_hash）签进回执，供 Provider 审计凭证是否被越权使用；网络拓扑不属于授权语义，混入会污染哈希的语义稳定性。Agent 地址变更不应导致回执校验体系的任何波动。

---

## 5. Hub↔TEE 数据面：请求模式与流模式

### 5.1 请求模式（已有，线格式冻结）

POST /v1/execute：请求体是 CBOR 编码的 ExecuteRequest（JobSpec 加 Body），响应是 SSE 事件流——data 帧逐块携带上游响应体字节，末尾以 receipt 帧携带签名回执。每个用户请求对应一次调用；TEE 在 (provider, host) 对应的 Channel 上执行一个 HTTP 请求。Hub 侧既有业务链条（配额 → 派发 → 验签 → 流哈希比对 → 计价 → 落库）完全不变，hub.TEE 接口不变，ScriptedTEE 替身与毫秒级单测体系继续适用。

### 5.2 流模式（新增）：WebSocket 透传会话

面向 WebSocket 型上游的全双工会话，过程分三段。

建连段。Hub（按最低价选定 Provider 后）向 TEE 请求开流通道，请求里携带一份完整 JobSpec（Method 为 GET、目标路径、Stream 为 true）与空 body——与请求模式走完全相同的校验、授权、凭证注入路径，凭证注入进 HTTP Upgrade 请求头；TEE 经该 Provider 的 Agent 拨号、完成 TLS 握手、写出 Upgrade 请求、验证 101 响应。之后这条 TLS 连接从「HTTP 请求响应通道」切换为「透明字节管道」。

透传段。Hub 与 TEE 之间建立一条 WebSocket（复用仓库已有的 gorilla/websocket 依赖）：上行帧由 TEE 加密后原样发往上游，下行密文解密后原样回给 Hub。TEE 在此段不做任何帧解析——WebSocket 的 ping/pong、消息分片、关闭握手、JSON 语义全部由 Hub 处理。TEE 只做三件事：TLS 记录层、双向字节计量、下行明文的流式摘要。

收尾段。任一侧关闭后，TEE 签发会话回执：复用现有 Receipt 结构——StatusCode 记 101，RequestBytes 记上行字节总量，ResponseBytes 与 ChunkCount 与 StreamHash 记下行（摘要只覆盖下行明文字节，与既有响应摘要契约一致），ProviderSeq 照常递增。Hub 凭回执与实际转发的字节做验签比对，再解析 usage 计价入账。会话与通道的绑定可使用 Receipt 的保留键位（既有键号表 21–26 中预留的 SessionRef 一类），列为 P1 可选。

由此，「WebSocket 交互交给 Hub」在连接驻留约束下的正确形态被确定下来：**Hub 处理帧语义，TEE 只搬运加密字节。** TEE 的性能消耗压到理论下限（对称密码加计数），而密钥全程不出 TEE——这正是本次设计修订想要同时拿到的两端。

---

## 6. Hub 业务补全

对照产品需求，Hub 侧有三个缺口，全部是纯 Hub 逻辑，不触碰 TEE 接口。

第一，最低价调度。产品要求「对某个模型选择卖出价格最低的 Provider」。Provider Policy 的 RateCard（CBOR 键 12）已含每个 Provider 的 PerRequestMicros 与 ModelPremiumMicros，数据齐备，缺的是决策器：新增 dispatch 逻辑，给定模型把候选 Provider 按有效价（PerRequest 加模型加价）升序排列，执行时按序尝试，失败回退次低价。全部可用 ScriptedTEE 毫秒级单测。

第二，固定比例抽成。产品要求「向买家收取高于卖价的固定比例」。计价扩展为：买家应付 = 卖家价 × (1 + 佣金率)，沿用整数微单位运算与既有溢出检查（溢出报错而非回绕）；Ledger 的 Snapshot 在现有 dispatch/verified/settled 计数之外增加两个口径——Provider 结算额（等于卖家价）与佣金收入。佣金率进 Hub 配置。

第三，用户面 API。cmd/hub 从一次性 CLI 升级为常驻服务：暴露 OpenAI 兼容端点 POST /v1/chat/completions（SSE 流式透传），请求体中的 model 字段驱动调度，tenant 从用户 API key 解析（首版用占位头，鉴权体系后置）。CLI 模式保留——harness 与既有场景依赖它。

---

## 7. 本地全栈仿真

仿真的目标是：一条命令拉起 Provider Agent、TEE、Hub、假 AI 服务商的完整链路，在本机（Apple silicon）验证全部结构性设计，且不需要任何真实模型。

组件与端口沿用现状：mockprovider（TLS，自建测试 CA）18080；TEE 18090；faketee 18091；Agent 18092 与 18093（双 Provider 场景用）；新增 Hub 常驻服务默认 18085。状态统一落 .sim 目录（可用环境变量重定向）。TEE 进程装配为：simulated 平台适配器 + 文件 SeqStore + ChannelManager + ProviderRegistry 文件装载——单进程单命令拉起，无外部依赖。仿真不要求证明的正确性（simulated 适配器的既有立场：证据字段结构与真实报告一一对应，只换信任根不换代码路径），但业务代码路径与真实 TEE 完全一致。

假 AI 服务商（mockprovider）在既有固定内容 SSE 与故障注入（401、429、truncate、slow、big）之上扩展两件事。其一，连接计数：监听器维护 TCP 连接总数，经 /stats 端点以 JSON 暴露——它把「连接驻留」从口头论断变成可执行断言。其二，WebSocket 端点 /v1/realtime：按脚本推送固定帧序列后正常关闭，供流模式端到端使用。不引入真实 LLM（大语言模型），返回固定内容是既定要求。

harness 新增三个场景，编号接续现有 1–12。场景 13（连接驻留）：同一 Provider 连发 N 个请求，断言 stats 恰好显示 1 条 TCP 连接；中途注入一次断流（fault=truncate），断言该 Channel 作废、下一请求走新连接（连接数加一）、截断回执 completion=truncated 且其后回执恢复正常。场景 14（流模式）：Hub 常驻服务 → TEE 流通道 → mockprovider 的 WebSocket 固定帧；断言帧序完整、会话回执离线验签通过、Agent tap 文件中零明文命中（复用场景 9 的 grep 机制）。场景 15（最低价与抽成）：两个 Provider——两个 Agent、两份签名 Policy、不同 RateCard——指向同一上游；断言全部请求选中低价者、回执的 provider 字段为低价者、Ledger 快照含佣金口径。

一键运行入口保持不变：bash tokenhive/harness/harness.sh 跑全部场景；go test ./tokenhive/... 跑单元与跨包测试。

---

## 8. 切换到真实云 TEE

platform.Adapter 与 platform.Epoch 抽象已就位，simulated 与 sevsnp（AMD SEV-SNP，基于 AMD 安全加密虚拟化的可信执行环境）两个适配器并存，本计划不改动这层。切换原则：新增组件（ChannelManager、ProviderRegistry、流模式服务端）只依赖 platform 抽象与标准库，不得出现仿真专用分支逻辑；真实接入的改动集中在 cmd/tee 的装配层（适配器选择 flag 或环境变量）与部署层（复用 deploy/ 的可复现构建机制，镜像摘要即 enclave 身份）。本机无法模拟 SEV-SNP 硬件证明（Apple silicon 无 AMD 安全处理器），这条边界早已明确，不影响仿真价值——业务与连接逻辑在仿真里已经全量执行。

真实 TEE 上线前的核对清单：签名 Epoch 改由 sevsnp 适配器的 Snapshot 提供；Hub 与 TEE 之间启用 mTLS（适配器的 ServerTLSConfig）；attestation evidence（远程证明证据）的取回接口补齐——这是既有记录在案的 P0 缺陷（回执默认不含证据时无法离线验证），属于切换清单的一部分；Channel 的 TLS 根证书从测试 CA 换为系统根（生产上游是真实的 OpenAI 证书链）。

---

## 9. 实施阶段与验收

阶段 C1（Channel 化，最优先）：transport 重构——channel.go 取代 http.go，socks5.go 与既有的四个「显式关闭标准库行为」约束以手工序列化的形式天然保留；跨包集成测试迁移到新 transport；mockprovider 增加连接计数与 /stats；harness 场景 13。验收：go test ./tokenhive/... 全绿；既有 12 场景不回退；场景 13 通过。

阶段 C2（Hub 业务）：最低价调度、抽成、Hub 常驻用户面 API；ScriptedTEE 扩展多 Provider 单测；harness 场景 15。验收：调度与账务规则全部有毫秒级单测覆盖；场景 15 通过。

阶段 C3（流模式）：Upgrade 隧道、会话回执、mockprovider 的 WebSocket 端点、harness 场景 14。验收：流式全链路通过、tap 零明文、会话回执可离线验签。

阶段 C4（真实 TEE 准备）：第 8 节清单逐项核对与文档化，不要求本机执行，为云上实机部署留好装配开关。

顺序依据：C1 是结构性根基且不破坏任何既有契约（tee.Transport 接口与 /v1/execute 线格式冻结），先落地；C2 与 C3 是纯增量，可并行；C4 是装配与部署收尾。

---

## 10. 与既有文档的关系

继续有效并直接复用：回执体系与全部 CBOR 键号决策（JobSpec 键 1–13、15、16，键 14 永久作废；Receipt 键 1–18；Policy 键 12 RateCard）；Provider Policy 承载定价权、Policy 执行点留在 TEE 的定案；SOCKS5 CONNECT-only Agent 及其 tap 抓包断言机制；simulated 平台适配器与「证据字段一一对应、只换信任根」原则；三层测试法（fake TEE 毫秒级业务测试、真 TEE 进程可信属性测试、接缝测试）；S5 基准与硬门禁（证明体积小于 2KB、回执生成 p95 小于 5 毫秒）。

被本文件修订：「TEE 是无状态纯字节层」的表述升级为「无业务状态、有受控连接状态」——Channel 与 ProviderSeq 同类，都是被窄接口隔离的 TEE 内状态；「每 job 一次独立 exchange、连接是 HTTP 客户端连接池的内部细节」的连接观废弃；一切「TEE 完成握手后把会话（含 TLS 密钥）移交 Hub」的设想正式否决。

新增：ChannelManager、ProviderRegistry、流模式数据面与会话回执、Hub 最低价调度与抽成、Hub 常驻用户面 API、mockprovider 连接计数与 WebSocket 端点、harness 场景 13–15。

---

## 11. 风险与边界

手工 HTTP/1.1 的分帧风险。自写部分只有请求序列化（无自动行为恰是安全属性），响应分帧交给 http.ReadResponse 由标准库消化；截断、超尺寸、chunked 各有既有场景兜底（场景 10、12），C1 补齐 Keep-Alive 复用与作废重建的专项断言（场景 13）。

仅支持 HTTP/2 的上游不可用。ALPN 锁 1.1 是显式连接模型的前提；主流 AI API 兼容 1.1，h2 多路复用留待后续，与既有文档判断一致。

长连接与故障的组合。断流后的半开连接必须整体作废——场景 13 有专项断言；Agent 被杀的行为保持现状（场景 10）：签发 completion=failed 回执，进程不挂起。

空闲窗口的取值。过短则「连接一直保持」名存实亡，过长则占用 Provider 出口资源——对 Provider 保持善意是平台义务。默认数分钟、可配置，真实运营时按 Provider 意愿调整。

业务规则的测试策略。调度、抽成、会话计价全部 ScriptedTEE 化，不碰网络——业务规则最易反复修改，必须留在毫秒级测试循环里，这是三层测试法的既定立场，流模式也不例外（ScriptedTEE 增加流式替身）。
