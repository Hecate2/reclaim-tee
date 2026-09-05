# TokenHive 架构：反向隧道连接与本地全栈仿真

日期：2026-09-03
状态：当前架构定稿

定位：本文是 TokenHive 当前架构的集中描述——连接如何建立、由谁持有、经过哪几跳、各组件的最低职责是什么。本文只描述系统现状，不保留任何历史改动的足迹。回执体系与 CBOR 键号、Provider Policy 与定价权、配额与账本、三层测试法这些已定案的内容继续有效，本文在涉及时给出它们的现状与位置，不逐一重复其推导。

---

## 0. 术语约定

首次出现时给出全称，后文直接使用缩写。TEE（Trusted Execution Environment）即可信执行环境；TLS（Transport Layer Security）为传输层安全协议；WebSocket 为在单条 TCP 连接上提供全双工通信的应用层协议；SSE（Server-Sent Events）为服务器推送事件流；CBOR（Concise Binary Object Representation）为确定性二进制编码（RFC 8949）；ALPN（Application-Layer Protocol Negotiation）为 TLS 的应用层协议协商扩展；mTLS 为双向认证的 TLS。JobSpec 为 Hub 交给 TEE 的作业描述；RateCard（费率卡）为按 provider 记录的定价数据；Receipt 为 TEE 签发的带证据的作业回执；ProviderSeq 为 TEE 内的单调序号；attestation（远程证明）为 TEE 向外部证明自身代码与配置身份的证据机制。

---

## 1. 部署形态：Provider 在家庭网络，反向隧道

TokenHive 的 Provider（AI 服务商配额贡献者）运行在自己的家庭网络里，位于 NAT 之后，不能被外网拨入。因此连接的方向被整体颠倒：**Provider Agent 主动拨向 Hub 并保持一条长连接；Hub 永不拨向 Agent。**这条 Agent 先行建立的连接是系统的枢纽。

上游服务商看到的源 IP 是 Provider Agent 的出口地址——这是产品成立的根本：TEE 的请求经由贡献者的出口到达 AI 服务商，贡献者因为出借出口而获得报酬。因为该出口不可被外网直连，Agent 必须先拨入 Hub 才能被寻址，也就带出了反向隧道的必要性。

端到端的一条请求链路如下。TEE 需要向某个 Provider 的上游发起连接时，它拨向 Hub 的中继端点开一条流；Hub 把这条流桥接进该 Provider 在线 Agent 的反向隧道；Agent 在其隧道上收到开流请求后，拨向它允许的上游 host；TEE 在这条流之上完成与上游的 TLS 握手并全程持有。

```text
User ─HTTP/SSE 或 WS─► Hub ─┬─ /v1/execute（请求模式）─► TEE ──┐
                            └─ /v1/session （流模式）─► TEE ──┤
                                                        ┌──────┴──────┐
                                                        │   Hub  中继  │  /v1/relay（TEE 拨入）
                                                        └──────┬──────┘
                                                        ┌──────┴──────┐
                                                        │  Agent 隧道  │  /v1/agent（Agent 拨入）
                                                        └──────┬──────┘
                                                                 ▼
                                                          上游 AI 服务商（OpenAI）
```

连接的所有权是本图的关键。TEE 到上游的 TCP 连接与 TLS 会话由 TEE 独占持有、跨请求长存；Hub 与 Agent 都只搬运这条连接的加密字节，永不接触 TLS 密钥；Hub 侧不存在任何到上游服务商或到 Agent 的出站连接。

两种数据面模式共享同一套数据面。请求模式承载 HTTP 请求—响应型 API（如 /v1/chat/completions 的 SSE 流式补全）；流模式承载 WebSocket 型上游（如 Realtime 类全双工会话）。两种模式都走同一条反向隧道，差别只在连接上承载的字节组织方式。

---

## 2. 反向隧道的实现：多路复用隧道

许多条并发的 TEE↔上游连接同时流经一条 Agent↔Hub 长连接，因此这条连接必须能多路复用。实现是 tokenhive/tunnel 包：一个自定的分帧协议，在单条全双工字节流上承载多条独立断开的双向字节流（Stream）。

分帧为 13 字节头（kind 一字节、8 字节流 ID、4 字节长度）加载荷。三类 frame：KindOpen 打开一条新流（载荷为打开端携带的不透明元数据，接收端把新流连同元数据交给其 open handler）；KindData 携带流上的载荷字节；KindClose 结束一条流。一条流对应一个 TEE 需要的独立字节管道；读测序由一个分发 goroutine 统一做，写侧由一把锁串行化，保证并发写不交错。

流的身份在两端免碰撞：Low 端在 ID 空间下半分配，High 端在上半分配，双方各自单调递增。背压由每流缓冲上限兜底（超过则发送方等待）；任一侧关闭后，流的读写侧在排空缓冲后返回 io.EOF。多路复用器整体关闭或底层连接失败时，所有在途流一并中断。

传输层适配是可替换的：生产用 WebSocket（tokenhive/tunnel/ws.go 把连接包装成连续字节流，一条 binary 消息对应一次 Write，读侧把消息拼接为连续流），测试可用 net.Pipe。分帧协议本身对载荷内容不敏感，因此它既承载控制流（Agent 注册、开流元数据）也承载数据流。

---

## 3. 组件与职责分界

各组件的最低职责是系统的稳定面，本节是集中陈述。

**TEE（TEE 进程）**：只负责建立并保持到上游的连接，以及作为连接上的字节层。具体是：凭证注入、Policy 白名单判定、JobSpec 结构校验与 body_hash 绑定、TLS 记录层、HTTP/1.1 请求序列化与响应分帧读取、流式摘要与回执签名、ProviderSeq 单调序号、连接（Channel）生命周期管理。TEE 对流式会话只做 TLS 加解密、双向字节计量与下行明文摘要，不解析任何 WebSocket 帧。TEE 不可见 model、不可见 tenant、不可见任何账务字段——JobSpec 是纯粹的「要执行的 HTTP 请求」描述（键 1–15，其中键 15 是随作业携带的加密凭证信封，见第 7 节）。

**Hub**：持有全部需要理解业务语义的逻辑。用户面 API（/v1/chat/completions、/v1/messages、/v1/responses、/v1/session、/v1/models 模型目录）、模型到 Provider 的最低在线价调度、配额、计价与佣金、账本、回执审计、usage（token 用量）解析、重试与故障回退。Hub 还承担反向隧道的两端服务器角色（见第 4 节）：Agent 拨入的注册门（AgentGate）与 TEE 拨入的中继端点（TeeRelay）。Hub 只持有加密的凭证信封（见第 7 节，键 15），永不见明文 token、不接触 TLS 密钥。

**Provider Agent（tokenhive/provider）**：纯粹的反向隧道客户端。拨向 Hub 的 AgentGate 并保持一条多路复用 WebSocket；注册上线后，对 Hub 在隧道上打开的每条中继流，拨向一个固定的允许列表（allowlist）之内的上游 host，然后双向复制字节。Agent 不读取所搬运的字节——TEE 与上游之间的 TLS 会话端到端加密，Agent 只看到自己并未参与会话的一段密文。Agent 强制执行且只强制执行一件事：allowlist，杜绝把贡献者机器变成通用代理。注册时可**可选声明**自己的上游能服务哪些模型（见第 4 节）；从 CLI 不带 `-models` 启动即视为配置了自动发现：Agent 在拨 Hub 之前向上游惯例的 `/v1/models` 端点拉取一次模型清单，**拉取失败或列表为空即报错并拒绝上线**——一个无法证明自己能服务什么的 Agent 绝不静默地以"服务一切"注册。注册消息未携带模型清单的 Agent（内嵌 provider 包、不配置自动发现的形态），Hub 视为服务任何模型。

**上游服务商**：只看到 Provider 的出口 IP 与其发来的请求，不知 Hub 与 TEE 的存在。

职责呈现为一条清晰的界：TEE 是连接的建立者与保持者、字节的搬运者与计量者；Hub 是语义的持有者（调度、计价、帧语义）；Agent 是密文的纯转发者。Provider 的凭证只在 TEE 手里，密钥不出 TEE，计价与资源边界全部落在 Hub 侧账本上。

---

## 4. Hub 的反向隧道服务器

Hub 侧维护两个 WebSocket 端点，这是它作为「NAT 背后贡献者和 TEE 的汇合点」的存在方式。两端的处理逻辑在 tokenhive/hub/agenthttp.go 与 agentnet.go。

**AgentGate（/v1/agent）**：Agent 拨入以在线。握手时校验 Agent 预设的共享密钥（agentKeyMatches 做常数时间比较，任何与 Hub 的 AgentSecret 不匹配的握手中断），随后把连接包成多路复用隧道，等待 Agent 的第一条控制流。控制流的开流元数据是 AgentRegister——它声明为哪个 provider 出口、可选展示名、可选的自我报价（SelfPrice）、**可选的模型清单（Models）**，以及**密封在 `Credential` 里的 token**：Agent 从 Hub 的 /v1/credential-key 拉取 TEE 收件公钥，把自己的 token 加密成凭证信封（tee.EncryptCredential）后随注册上报，Hub 只把密文信封存入凭证库、永不见明文。Models 是软能力提示：非空时该 Agent 只作为这些模型的候选；为空则该 Agent 服务任何模型。控制流保持打开期间该 Agent 视为在线；控制流一旦关闭，Agent 从调度器离线、隧道拆除，Hub 同时从凭证库撤销该 provider 的信封。Agent 未声明自价时接受 Hub 为该 provider 声明的平台默认价；若 provider 无平台默认价，该 Agent 无法注册。

在线注册表（agentRegistry）以 provider 为主键：同一 provider 任一时刻只有一个在线 Agent，后注册者顶掉先前者并关闭其隧道（杜绝同一 provider 的双重身份与陈旧隧道）。每个在线 Agent 连同其有效价与声明的模型清单一起登记，调度器只把新工作路由到此刻在线且（若声明了清单）清单含该模型者。

**TeeRelay（/v1/relay）**：TEE 拨入以承载出站。TEE 的每条流以 RelayOpen 元数据打开，声明要走的 provider 与上游 host；Hub 查在线注册表拿到该 provider 的 Agent 隧道，以同名的上游 host 作为 UpstreamOpen 打开一条中继流，然后把两条对向复制。中继只搬密文。如果该 provider 当前无在线 Agent，Hub 直接关闭这条流（ErrAgentOffline），调用方（transport）视为普通连接失败并交给下一个候选 provider。

两个端点的 WebSocket 升级均使用传入的 Upgrader（跨进程/测试共享）。生产环境 Hub 与 TEE、以及 Hub 与 Agent 之间应置于受信网络边界之内（TeeRelay 尤其应落在与其余 Hub↔TEE 通道相同的 mTLS 后；见第 9 节）。

---

## 5. TEE 侧的出站路径

TEE 的出站不再知道任何 Agent 地址；它只有一个 Hub 中继端点。tokenhive/transport 拆成两层。

ChannelManager（transport/channel.go）持有连接驻留语义：以 (provider, host) 为键的通道池，空闲连接在窗口内不关闭（连接「一直保持」由此落实），同一时刻一条 HTTP/1.1 连接承载一个在途请求，异常后整体作废不再复用半开连接。它满足 tee.Transport 与 tee.SessionOpener 两个接口，tee.Service 主体流程（校验 → 授权 → 注入 → 执行 → 摘要 → 签回执）与 /v1/execute 线格式不因连接模型而变。

Relay（transport/relay.go）是 ChannelManager 的拨号器：持有与 Hub TeeRelay 的一条持久多路复用隧道，把每条 (provider, host) 拨号变成隧道上的一条流，以 net.Conn 的表面（streamConn）交还给 TEE，让 TLS 握手照常在 TEE 内完成。隧道掉线则重建一次并重试该流。TLS 永远在 TEE 内终止——Hub 与 Agent 看到的都是这条 TLS 会话的密文。

ChannelConfig 的 egress 配置：RelayURL（经 Hub 中继，生产形态与本地仿真均如此）；不设 RelayURL 时 ChannelManager 直连 req.Host（仅用于嵌入式 transport 测试与同机模拟）。无论走隧道还是直连，TLS 都在 TEE 内终止，隔离性相同。

---

## 6. 业务规则：最低在线价调度与账务

调度、计价、账务全部在 hub 包内，全部可在 ScriptedTEE 毫秒级单测中验证，不经网络。

**最低在线价调度**。用户只声明 model，不声明 provider。providersForModel 产出候选：**供应 = 此刻持有一条在线隧道的 Agent**——离线即退出候选，挂单（自报价）随之消失，绝不回落到市场默认价继续调度（一个无人持有隧道的 provider 不该收到任何新作业）。按有效价（PerRequestMicros 加该 model 的加价）升序排列，同价按 provider 名破序使顺序成为供应的纯函数。在线 Agent 的自报价即其有效价（h.card 同时供调度与结算读取，报价与实收不漂移）。唯一的例外是**不承载 Agent 注册的 Hub**（未配置 AgentSecret，如仅对脚本替身的嵌入业务测试）：它没有"在线"概念，直接用静态市场表做供应，让单测在不引入真实隧道的前提下验证定价与排序。ExecuteForModel 按序尝试，失败回退次低价；一旦某 provider 的首个字节已被透传给用户，即视为已绑定该 provider，不再中途切换（避免两份回执拼凑一个用户不可解析的响应）。

**声明的模型 = 软能力过滤**。Agent 注册时可声明 Models；声明过的 Agent 只作为清单内模型的候选（发一个它上游没有的模型只会白买一次拒绝），未声明的 Agent 服务任何模型。当某模型不在任何在线 Agent 的清单里时，请求以"无 Provider 服务该模型"拒绝，而不是朝每个 provider 各打一枪。买家的**模型目录 `GET /v1/models`** 就建立在这份声明之上：列出所有在线 Agent 声明过的模型，每行带调度器此刻实际会派发的最低在线价与对应 provider；目录完全由 Hub 内存中的在线注册表算出，**不向任何 Agent/上游发起探测**（买家的浏览动作不产生任何询价流量）。可选 `?q=` 子串查询在目录上做大小写不敏感的包含匹配，供买家按精确 ID 或名称片段（"deepseek" 命中 "deepseek-pro"/"deepseek-flash"）检索。

**计价与佣金**。买家应付 = 卖家价 ×（1 + 佣金率）。沿用整数微单位与溢出检查（溢出报错不回绕）。账本（Ledger）记录 dispatc/verified/settled 计数、以及按 provider 的收入口径与 Hub 佣金口径；Provider 始终拿到自己费率卡上的全额，佣金单独追踪。

**配额与回执**。配额在派发前检查，被拒请求不消耗 ProviderSeq——否则节流会在 provider 序列上穿孔，与 Hub 隐藏执行不可区分。回执在一切结算前验签与字节比对（MatchesStream 对先在足，流式摘要与 Hub 实际转发字节必须一致），对不上的回执一律不结算。

---

## 7. JobSpec 与键号现状

JobSpec（tokenhive/jobs/spec.go）是 Hub 交给 TEE 的作业描述，其哈希签进回执，供 provider 事后核对凭证用途。它是「凭证使用授权」的载体，不携带任何网络拓扑或账务元数据。

现有键号连续编号 1–14：1 Version、2 JobID、3 Provider、4 Method、5 Host、6 Path、7 Query、8 Headers、9 BodyHash、10 Nonce、11 ExpiresAt、12 MaxResponseBytes、13 Stream、14 Session。没有空缺、没有作废编号。键随规格的演进重新连续编号是刻意的：键号属于线格式的一部分，一旦发布不可重用或重编号；当前连续 1–14 是发布时点的确定性快照。

Session（键 14，omitempty）标记流式 WebSocket 型会话请求：置位时 TEE 对上游做 HTTP Upgrade 握手而非普通请求，然后中继一条不透明双向字节管道。握手的帧与内容语义（掩码、分片、关闭握手、JSON）全部归 Hub；TEE 只搬运、计量、摘要。会话作业的 body 必须为空——它是一次握手，没有载荷。

---

## 8. 本地全栈仿真（harness）

仿真的目标是一条命令拉起完整链路在本机（Apple silicon）验证全部结构性设计，无需任何真实模型。组件与端口沿用：mockprovider（TLS，自建测试 CA）18080、其平文 /stats 18081（探测不扰动所报告的值）；faketee 18090；TEE 进程若干（18095、18096、18097、18098、18099、18091 等）；cmd/hub serve 默认 18085（同时挂载用户 API、/v1/agent 门、/v1/relay 中继）。状态统一落 .sim 目录（可用环境变量重定向）。

仿真的装配原则：cmd/hub serve 以 -agent-key 启动，同时挂载 AgentGate 与 TeeRelay；Provider Agent 以 -hub、-key、-provider、-targets 拨入；真实 TEE 以 -relay ws://…/v1/relay 出站。三个角色（hub、agent、tee）的 CLI 参数即反向隧道拓扑的可读表达。仿真不要求证明的正确性（simulated 适配器的既定立场：证据字段结构与真实报告一一对应，只换信任根不换代码路径），但业务代码路径与真实 TEE 完全一致。

harness 场景矩阵覆盖：正常流、策略拒绝、provider 故障（401/429/truncate）、跨重启 ProviderSeq 续增、序列空洞审计、配额、真实 TEE 经反向隧道 + tap 抓包断言（Agent 只见密文、零凭证命中）、Agent 中途被杀优雅失败、epoch 轮换、超尺寸响应截断、连接驻留（N 请求恰一条上游 TCP 连接、断流后作废并重拨）、流模式会话、最低价调度与抽成、Agent 不带 -models 自动发现（经仿真 CA 拉上游 /v1/models）并登记模型目录、买家按精确/子串搜索目录。三层测试法不变：fake TEE 毫秒级业务测试、真 TEE 进程可信属性测试、接缝测试。一键运行入口为 bash tokenhive/harness/harness.sh；go test ./tokenhive/... 跑单元与跨包测试。

---

## 9. 安全边界与加固项

系统当前的安全边界按职责划定，并保留若干明确的加固项。

TEE 持有的凭证与 TLS 密钥不出 TEE；Agent 只看到密文，LaaS 无从越权读取注入头；JobSpec 无账务字段，TEE 无从泄露 model/tenant；回执的流式摘要 + body_hash 绑定 + ProviderSeq 单调性构成 provider 事后核对凭证未被越权使用的四段证据链（出口一致性、Policy 白名单绑定 attestation、回执签名与字节摘要、凭证用途自证）。

Hub 的 AgentGate 以共享密钥为门，拒斥未持密者的拨入。当前 AgentSecret 是单一全局密钥，注册不绑定 per-provider 身份——任何持此密钥者可冒名注册任意 provider（顶掉该 provider 在线隧道并可能截获其流量）。这与注释声明的「共享密钥是唯一身份凭证」一致，但对贡献者开放前应改为 per-provider 密钥或 Hub 端固定 provider↔key 映射（Upstream 加固项 1）。

Hub 的 TeeRelay 依赖网络边界自证（受信的 Hub↔TEE 通道）。任何能连到该端点的调用方凭 provider+host 可开一条到某在线 Agent allowlist 内主机的流；防线目前只有 Agent 的 allowlist。应把 TeeRelay 与其余 Hub↔TEE 通道放在同一 mTLS 之后（Upstream 加固项 2，与既有「生产启用 mTLS」的部署边界一致）。

切换真实云 TEE 的核对清单照旧效仿：签名 Epoch 由 sevsnp 适配器提供，Hub↔TEE 启用 mTLS，attestation evidence 取回接口补齐，Channel 的 TLS 根证书换为系统根。

---

## 10. 风险与边界

**手工 HTTP/1.1 的分帧风险**。请求侧自写部分只有序列化（无自动行为恰是安全属性），响应分帧交给 http.ReadResponse 由标准库消化；截断、超尺寸、chunked 有既有场景兜底，连接驻留补充 Keep-Alive 复用与作废重建的专项断言。

**仅支持 HTTP/2 的上游不可用**。ALPN 锁 1.1 是显式连接模型的前提；主流 AI API 兼容 1.1，h2 多路复用留待后续。

**长连接与故障的组合**。断流后半开连接必须整体作废；Agent 被杀时 TEE 签发 completion=failed 回执，进程不挂起。

**空闲窗口取值**。过短则「连接一直保持」名存实亡，过长则占用 Provider 出口资源；默认数分钟、可配置，真实运营按 Provider 意愿调整。

**多路复用的背压**。单流缓冲超过上限即停顿发送方，避免一条慢流占用整条隧道的缓冲；关闭语义保证流独立结束不互相拖累。