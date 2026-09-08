# TokenHive 真实 TEE 部署与测试手册（AWS SEV-SNP）

日期：2026-09-08
状态：已在 eu-west-1 实测通过（build → up → verify → down 全流程）

定位：本文是从零开始部署并测试真实 TEE（Trusted Execution Environment，可信执行环境）的完整操作手册。起点是信任根密钥的创建，终点是在 AWS 上完成一次真实 SEV-SNP（Secure Encrypted Virtualization-Secure Nested Paging，AMD 的安全加密虚拟化-安全嵌套页）机密实例的启动、远程证明（attestation）验证与清理。文中给出每一步的精确命令、需要的 AWS 权限、以及实测中遇到的故障与解法。

---

## 0. 术语约定

首次出现时给出全称，后文直接使用缩写。TEE（Trusted Execution Environment）即可信执行环境；SEV-SNP（Secure Encrypted Virtualization-Secure Nested Paging）为 AMD 提供的基于安全加密虚拟化与安全嵌套页的机密计算技术；attestation（远程证明）为 TEE 向外部证明自身代码与配置身份的证据机制；AMI（Amazon Machine Image）为 AWS 的可启动镜像；UEFI（Unified Extensible Firmware Interface）为统一可扩展固件接口；Secure Boot 为基于 UEFI 数字签名的安全启动机制；PK（Platform Key）为 Secure Boot 的顶级平台密钥；KEK（Key Exchange Key）为密钥交换密钥，连接 PK 与签名数据库；db（Signature Database）为签名数据库，列出被信任的签名者证书；UKI（Unified Kernel Image）为统一内核镜像，把内核、initrd（初始内存盘）与命令行打包为单个 UEFI 可执行文件；PCR（Platform Configuration Register）为 TPM（Trusted Platform Module，可信平台模块）内的平台配置寄存器，度量值只能扩展不能回退；RATLS（Remote Attestation TLS，远程证明传输层安全）为把 attestation 证据绑定进 TLS（Transport Layer Security，传输层安全协议）握手的机制；VM Import 为 AWS 提供的把外部虚拟磁盘导入为 EC2 快照与 AMI 的服务；ESL（EFI Signature List）为 EFI 签名列表，Secure Boot 数据库中证书的载体格式；VMDK（VMware Virtual Disk）为 VMware 虚拟磁盘格式；boto3 为 AWS 官方的 Python SDK；IAM（Identity and Access Management）为 AWS 的身份与访问管理服务；S3（Simple Storage Service）为 AWS 对象存储服务；EC2（Elastic Compute Cloud）为 AWS 的云服务器服务。

---

## 1. 全流程概览

TokenHive 的真实 TEE 测试在云上复现了一条完整的信任链：从固件到应用，每一步的测量值都可由远程验证者核验。镜像采用两层 loader 设计，其核心思想是把"引导链"与"应用"分离成两个独立的部分。第一层是一个由信任根 R 签名的基础 UKI（统一内核镜像），它包含内核、initrd（初始内存盘）与 loader 程序，loader 作为 init 进程直接启动；第二层是一个独立的原始分区，里面存放应用的 bundle 归档（tar 包），不参与引导。loader 启动后读取该分区，对原始字节计算 SHA-256 摘要得到 SNP_APP_HASH，把它扩展进 TPM 的 PCR 8，然后以非特权身份执行应用，并把该哈希值注入应用进程的环境变量。应用在运行中调用 SEV-SNP 的 attestation 接口，生成一份由硬件签名的证据，并把 SNP_APP_HASH 绑定进证据的 report_data 字段，再自验证该证据。验证者只需要两样东西：信任根 R 的公钥（用于重放 Secure Boot 日志证明引导链合法），以及 PCR 8 的预期值（用于证明被加载的应用就是预期的那份字节）。

整套流程被编排进一个脚本 `snp.sh`，五个子命令对应五个阶段：

```bash
./snp.sh build          # 打包应用 bundle + 构建 loader AMI（依赖 VM Import）
./snp.sh up             # 启动带 AmdSevSnp 的机密实例（写入 hosts.json）
./snp.sh verify         # 轮询 EC2 控制台输出直到 SNP_TEST_RESULT，保存日志
./snp.sh down           # 严格按双 tag 终止实例（可先 --dry-run 预演）
./snp.sh delete-infra   # 清理带 tag 的网络基础设施（破坏性，慎用）
```

其中只有 `build` 需要本地的 docker、qemu-img 与 AWS CLI 以及 VM Import 全链路；`up`、`verify`、`down` 只需要 boto3 与 EC2 权限。删机永远只按双 tag（`tokenhive-TEE: true` 与 `user: <配置值>`）匹配，绝不依赖 hosts.json 临时文件，这是删除操作唯一的安全边界。

---

## 2. 信任根密钥的创建（最早的步骤）

Secure Boot 的信任体系是三级嵌套：PK（平台密钥）位于最顶层，只有持有 PK 私钥才能修改 KEK（密钥交换密钥）；KEK 授权对 db（签名数据库）的更新；db 中列出的证书是"被信任的签名者"，固件只启动由这些签名者签名的可执行文件。TokenHive 的信任根 R 就是这个体系中的签名者：R 的证书被放进 db，镜像的 UKI 由 R 的私钥签名，于是只要固件在 Secure Boot 模式下启动，未经 R 签名的代码就不可能被执行。

本仓库的 `deploy/secure-boot/` 目录下，PK 与 KEK 的密钥对（含证书、ESL、公钥）是仓库既有资产；R 是本模块的发布信任根，当私钥丢失或需要轮换时按以下步骤重建。所有命令在 `deploy/secure-boot/` 目录内执行。

第一步，生成 R 的 RSA-3072 私钥。SEV-SNP 实例（AMD EPYC 7003 系列）的固件要求 db 签名者使用 RSA 2048 或 3072 位密钥，3072 是当前强度下的稳妥选择：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out R.key
chmod 600 R.key
```

第二步，从私钥派生自签名的 X.509 证书。证书只含公钥与身份信息，是分发物；Common Name 建议用可读的发布者名，它会在验证者的日志与证据中出现：

```bash
openssl req -new -x509 -key R.key -out R.crt.pem -sha256 -days 3650 \
  -subj "/CN=Reclaim Cross-Cloud Release Key"
openssl x509 -in R.crt.pem -outform DER -out R.crt.der
openssl pkey -in R.key -pubout -out R.pub.pem
```

第三步，生成 EFI 签名列表 R.esl。Secure Boot 的 db 变量以 ESL 格式存放证书，需要绑定一个全局唯一标识符（GUID）；仓库的 GUID.txt 提供固定值，避免每次重建改变变量身份：

```bash
cert-to-efi-sig-list -g "$(cat GUID.txt)" R.crt.pem R.esl
```

第四步，同步发布公钥。`shared/secure_boot_release_pub.pem` 是验证方持有的 R 公钥，构建脚本会强制校验它与 `deploy/secure-boot/R.pub.pem` 完全一致（`cmp -s`），两者不一致构建直接失败，这是防止"签名密钥与验证密钥分叉"的护栏：

```bash
cp R.pub.pem ../../shared/secure_boot_release_pub.pem
```

第五步，重建 AWS 的 UEFI 变量存储 `aws-uefi-data.b64`。AWS EC2 的 `register-image --uefi-data` 参数接受一段 base64 编码的 NVRAM（非易失随机存取存储器）变量二进制，内含 PK、KEK、db 三组变量；db 中放入的就是上一步的 R.esl。用 python-uefivars 工具（pip 安装）把三个 ESL 按 UEFI 规范的 NVRAM 布局序列化，再 base64 编码写入该文件。注意这一步替换的是整个变量存储，PK 与 KEK 的内容保持不变，只更新 db 中的 R 证书：

```bash
pip install python-uefivars
# 用 uefivars 把 PK.esl、KEK.esl、R.esl 组装为 NVRAM 变量存储（db ← R.esl）
# 输出二进制经 base64 编码后写入 aws-uefi-data.b64
```

R.key 是唯一的秘密：它必须只存在于本机与构建机，绝不能进入版本库。仓库的 .gitignore 已用 `deploy/secure-boot/*.key` 模式将其排除；其余 R.crt.pem、R.crt.der、R.pub.pem、R.esl、aws-uefi-data.b64 均为公钥/证书材料，是分发物，与 PK、KEK 一样纳入版本管理，保证任何克隆仓库的人都能复现构建与验证。

---

## 3. AWS 权限需求（详细）

### 3.1 区域与实例约束

AWS 的 SEV-SNP 支持区域目前只有两个：eu-west-1（爱尔兰）与 us-east-2（俄亥俄）。其他区域即使启动成功也只是普通实例，没有硬件机密内存，因此区域是硬约束，配置在 `deploy/.env` 的 `AWS_SNP_REGION` 与 `cloudtest/.env` 的 `TOKENHIVE_REGION`，两者必须一致。实例类型限定 AMD EPYC 7003 系列的 m6a、c6a、r6a 家族，默认 c6a.large。

### 3.2 执行身份的最小策略

执行构建与测试的 IAM 身份（用户或角色）需要附加 `tokenhive/cloudtest/snp/iam/aws-snp-policy.json`。该策略按职责分为七个语句（Sid）：

**Identity**：`sts:GetCallerIdentity` 与 `ec2:DescribeRegions`，构建脚本用它解析当前账号 ID 以派生 S3 桶名，属于最小身份探测。

**VMImportBucket**：S3 桶操作，资源限定在 `snp-vmimport-*` 前缀。桶名规则是 `snp-vmimport-<账号ID>`，前缀限定保证该身份只能操作本模块的暂存桶，不能触碰其他业务桶。包含 `s3:CreateBucket`、`s3:ListBucket`、`s3:GetBucketLocation`、`s3:PutObject`、`s3:GetObject`、`s3:DeleteObject`。

**VMImport**：VM Import 核心动作，`ec2:ImportSnapshot` 发起快照导入，`ec2:DescribeImportSnapshotTasks` 轮询导入状态，`ec2:RegisterImage` 把导入完成的快照注册为 AMI，`ec2:DeregisterImage` 覆盖旧 AMI，`ec2:DescribeImages` 查询现有镜像。

**ReadAllEC2**：只读描述权限，覆盖实例、VPC、子网、互联网网关、安全组、路由表、可用区、密钥对、快照与标签，是幂等基础设施逻辑（先查后建）的前提。

**IdempotentInfra**：基础设施的创建与删除动作，包括 VPC、子网、互联网网关、路由表、安全组、密钥对的增删改。这些操作全部由 launch.py 以"存在则复用、不存在则创建"的语义调用。

**Instances**：实例生命周期，`ec2:RunInstances` 启动、`ec2:TerminateInstances` 终止、`ec2:GetConsoleOutput` 读取控制台输出（verify 阶段唯一的数据通道），以及 `ec2:CreateTags`/`ec2:DeleteTags` 维护双 tag。

**VMImportServiceRole**：创建并给 `vmimport` 服务角色附加策略所需的 IAM 动作，资源限定在 `arn:aws:iam::*:role/vmimport`，只允许操作这一个角色名。

### 3.3 vmimport 服务角色

VM Import 是 AWS 的托管服务，它需要以一个名为 `vmimport` 的 IAM 角色身份去读取 S3 桶并写入 EC2 快照。该角色创建一次即可，仓库 `tokenhive/cloudtest/snp/iam/` 下提供了两份现成的 JSON：

`vmimport-trust-policy.json` 声明信任策略：主体是 `vmimport.amazonaws.com` 服务，允许它执行 `sts:AssumeRole`，即允许 AWS 的 VM Import 服务以该角色身份工作：

```bash
aws iam create-role --role-name vmimport \
  --assume-role-policy-document file://vmimport-trust-policy.json
```

`vmimport-role-policy.json` 声明角色权限，两条语句：`ReadSourceS3` 允许从 `snp-vmimport-*` 桶读取对象（`s3:GetBucketLocation`、`s3:GetObject`、`s3:ListBucket`），`WriteEC2Snapshot` 允许写入 EC2 快照（`ec2:ModifySnapshotAttribute`、`ec2:CopySnapshot`、`ec2:DescribeSnapshots`、`ec2:RegisterImage`、`ec2:DescribeImages`）：

```bash
aws iam put-role-policy --role-name vmimport --policy-name vmimport \
  --policy-document file://vmimport-role-policy.json
```

### 3.4 实测踩过的权限坑

本次实测中，唯一一次构建失败根因是执行身份缺少 `s3:CreateBucket`。现象链条是：脚本里 `aws s3 mb ... || true` 把 AccessDenied 吞掉，随后 `aws s3 cp` 报出令人困惑的 `NoSuchBucket`，看起来像桶不存在，实际是建桶的权限没有。修复有两层：在 IAM 策略中补上 `s3:CreateBucket`（策略文件本就包含，只是没有真正挂载）；在构建脚本中去掉 `|| true` 的静默吞错，只对幂等重跑会出现的 `BucketAlreadyOwnedByYou` 宽容，其余失败直接打印并退出，让权限问题第一次发生就暴露根因。

另一个实测观察：如果执行身份连 `iam:ListAttachedUserPolicies` 都没有，就无法自查策略挂载情况。诊断权限问题建议从最小动作开始逐层探测：`aws sts get-caller-identity` 确认身份，`aws s3 mb` 确认建桶，`aws --region <region> ec2 describe-import-snapshot-tasks` 确认 VM Import 查询权限。

---

## 4. 环境与配置

两处配置文件都需要操作者填写，且都被 .gitignore 排除，不会进入版本库；仓库各自保留了模板（`deploy/.env.example` 与 cloudtest 目录内说明）。

`deploy/.env` 是构建侧配置。本模块必填项为 `AWS_SNP_REGION`，限定为 eu-west-1；`GCP_PROJECT` 在 AWS 路径只是占位（构建脚本会强制其非空但实际不用于 AWS）。另一个关键项是 APT 镜像源选择 `SNP_APT_MIRROR`：默认值 `snapshot` 会把 Ubuntu 软件源固定到 snapshot.ubuntu.com 的不可变快照（确定性基础镜像，可复现），当该站点经本地代理访问不稳定（实测大量 502）时，可切换为 `aliyun` 走阿里云实时镜像把构建跑通。这个切换只影响诊断用基础镜像的摘要，信任根 R 与应用 bundle 摘要完全不受影响；生产可复现构建应切回 `snapshot`。

`cloudtest/.env` 是测试侧配置。`TOKENHIVE_USER` 是唯一必填项，它既是实例 Name 前缀的一部分，更是删除安全边界的另一半（`user` tag 的取值），绝不能留空或误填；`TOKENHIVE_REGION` 默认 eu-west-1；`TOKENHIVE_INSTANCE_TYPE` 默认 m6a.large，实测使用 c6a.large。

`deploy/snp-image/pins.env` 锁定了构建链上每个工具的精确版本：内核包、systemd 的 stub 与 ukify、zstd、cpio、binutils、sbsigntool、efitools，以及基础镜像摘要与 Go 工具链版本。这些锁定保证同一份源码在任何机器上重建出字节一致的镜像。

---

## 5. 构建 AMI（snp.sh build）

构建阶段从打包应用 bundle 开始，到注册 AMI 结束，内部是一条完整的流水线。执行：

```bash
cd tokenhive/cloudtest/snp
env -u PYTHONHOME -u PYTHONPATH ./snp.sh build
```

（`PYTHONHOME`/`PYTHONPATH` 在本机环境中被其他工具污染，会导致基于 Python 的 aws CLI 崩溃，显式清空是稳妥做法。）

第一步，`pack.sh` 把 loader 探针程序（`runner/main.go`）交叉编译为静态 amd64 二进制，并用 Python 的 tarfile 模块打成确定性的 bundle 归档：文件按名称排序、owner/group 固定为 0、mtime 固定为 2025-01-01 纪元值。确定性是硬要求，因为 bundle 的 SHA-256 就是 SNP_APP_HASH 与跨云应用身份 `snp-app:<hash>`，同样的输入必须产出同样的摘要，否则验证方锚定的值无法被重建。这一步输出 `snp-app:6944dc93...` 格式的摘要行。

第二步，`deploy/snp-build.sh` 编译 Secure Boot loader（`deploy/snp-image/loader`），然后在 Docker 内完成两层镜像组装（`snp-image/Dockerfile` + `tier-build.sh`）：基础 initrd 以 loader 为 /init，打入 AWS 需要的非内置内核模块（ena 网卡驱动、tsm_report、sev-guest 的 SEV 设备驱动）；ukify 用内核与 initrd 组装 UKI，并用 R.key/R.crt.pem 通过 sbsign 签名，随后 sbverify 验证签名；systemd-repart 把磁盘组装为 ESP 分区（放置签名 UKI）与一个独立的 96MB 原始分区（CopyBlocks 写入 app bundle）。这一步的日志会打印三行关键摘要：`base_uki_sha256`（基础 UKI 摘要，随应用变化稳定）、`app_sha256`（应用 bundle 摘要，即 SNP_APP_HASH）、`expected_PCR8`（PCR 8 的理论预期值）。

第三步，云打包（AWS 路径）：`qemu-img` 把原始磁盘转换为 streamOptimized 的确定性 VMDK，并修正其中 CID 字段的格式问题（qemu 用 %x 写出的短 CID 会被 AWS 误判为带父盘引用的增量盘而拒绝）；幂等创建暂存桶 `snp-vmimport-<账号ID>` 后上传 VMDK；发起 `import-snapshot` 并轮询直到 completed（实测约 8-10 分钟）；最后用 `register-image` 注册 AMI，关键参数包括 `--boot-mode uefi`、`--tpm-support v2.0` 与 `--uefi-data "$(cat aws-uefi-data.b64)"`——正是这一步把包含新 R 证书的 UEFI 变量存储写进镜像，实例启动后固件加载的就是这份 db。

构建成功的标志是日志出现 `AMI <ami-id> (snp-tokenhive) registered`。

---

## 6. 启动机密实例（snp.sh up）

`launch.py` 先以幂等语义确保基础设施：VPC、子网、互联网网关、安全组、密钥对，全部"先查后建"，重复执行不会产生重复资源。随后以 `CpuOptions={"AmdSevSnp": "enabled"}` 启动实例——这是实例真正获得机密内存的开关，AWS 会在实例 tag 上自动打上 `aws:ec2:sev-snp: ec2-sev_snp` 作为已启用机密计算的标志。实例启动即带双 tag（`tokenhive-TEE: true` 与 `user: <配置值>`），实例信息写入 `cloudtest/hosts.json`（仅作信息记录，删除不依赖它）：

```bash
./snp.sh up
```

该镜像没有 sshd，也没有登录方式；实例是"一次性自检机"：启动 → loader 测量应用 → 生成并自验证 attestation → 把结果打到串口控制台 → 自动关机。验证阶段读取的就是这份串口输出。

---

## 7. 验证 attestation（snp.sh verify）

`verify` 子命令轮询 EC2 的 `GetConsoleOutput`，把每次抓取的控制台输出写进 `logs/<时间戳>/<实例ID>.console.log`，直到出现结果行或超时：

```bash
./snp.sh verify
```

实测得到的成功结果是：

```text
SNP_TEST_RESULT matched=yes attestation_type=secure-boot app_hash=6944dc931575609749e855d73a50b550a64ab97adb1b7185f121b8022c2c2d86
```

`app_hash` 与第 5 节构建时打印的 `snp-app:` 摘要完全一致，说明实例上被 loader 测量的字节与本地打包的字节逐位相同。控制台日志里可以读到完整的硬件证据链：`Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP` 与 `SEV: SNP running at VMPL0` 证明机密内存与 VMPL0 层级已激活；`secureboot: Secure boot enabled` 与 `Loaded X.509 cert 'Reclaim Cross-Cloud Release Key: 95f1c88a...'` 证明固件在 Secure Boot 模式下加载了 db 中的 R 证书（重建 aws-uefi-data.b64 的直接效果）；`extended PCR 8 with app_sha256` 证明 loader 完成了对应用的 TPM 度量；`app pid=89 uid=65532 broker pid=88` 证明根权限的 attestation broker 与普通权限的应用进程分流正确。这四行合在一起，就是"真实 TEE 在跑、跑的确实是我们打包的应用"的完整证明。

---

## 8. 清理（snp.sh down / delete-infra）

清理分两级。`down` 只删实例，`delete-infra` 才动网络基础设施（VPC、安全组等），两者都严格按双 tag 过滤。删除逻辑从不读取 hosts.json，只按 `tokenhive-TEE: true` 与 `user: <配置值>` 两个 tag 描述实例，其中 user 值必须与配置完全匹配——这是"绝不误删他人机器"的结构性保证，而不是约定俗成。先预演再执行是安全的操作习惯：

```bash
./snp.sh down --dry-run    # 列出将被终止的实例，什么都不删
./snp.sh down              # 真正终止（输出每台被终止的实例 ID）
./snp.sh status            # 随时确认双 tag 范围内的存活实例
```

实测一次完整测试后的收尾输出是 `terminated: i-070b6fa8d1bc1aed4`，随后 status 返回空，双 tag 范围内无残留。

---

## 9. 故障排查

**构建时 APT 大量 502**：snapshot.ubuntu.com 的不可变快照服务经本机代理访问不稳定。在 `deploy/.env` 设置 `SNP_APT_MIRROR=aliyun` 切换到阿里云实时镜像即可跑通；生产可复现构建切回 `snapshot`。

**上传 VMDK 报 NoSuchBucket**：几乎总是 `s3:CreateBucket` 权限缺失，而不是桶不存在。按第 3.4 节补权限，脚本现在也会直接把真实错误打出来。

**启动报不支持 SEV-SNP**：区域不对。SEV-SNP 只有 eu-west-1 与 us-east-2；实例类型必须是 m6a/c6a/r6a 家族。

**本地 aws CLI 崩溃（Python encodings 错误）**：`PYTHONHOME`/`PYTHONPATH` 被外部工具污染。执行前 `env -u PYTHONHOME -u PYTHONPATH` 清空。

**SNP_APP_HASH 未设置**：应用绕过了 loader 直接运行（例如手动放进 Ubuntu 镜像）。SNP_APP_HASH 由 loader 注入，只有被 loader 引导的应用进程才能拿到；本模块的探针正是为此验证"loader 注入的值与 attestation 绑定的值一致"。
