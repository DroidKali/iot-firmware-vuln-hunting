---
name: iot-firmware-vuln-hunting
description: 面向 IoT / 嵌入式固件的系统化漏洞挖掘流水线。当需要分析固件镜像、路由器 / 摄像头 / IPC / 智能门锁 / 智能家居设备固件、rootfs 镜像、嵌入式 ELF 二进制，或执行固件提取、静态审计、敏感信息与 SBOM/CVE 排查、模拟运行、网络服务模糊测试、漏洞验证与报告输出时使用。触发场景包括「帮我挖这个固件的漏洞」「分析这个路由器固件」「这个设备固件里有没有后门 / 硬编码口令」「固件安全评估」「firmware security assessment」等。
agent_created: true
---

# IoT 固件漏洞挖掘

## 这个 skill 解决什么

固件漏洞挖掘的难点不在于「看不懂代码」，而在于**没有一套系统化的工作流**。裸跑大模型分析固件会稳定复现五个失效模式：

| 失效模式   | 裸跑表现                                                   | 本 skill 的约束                              |
| ------ | ------------------------------------------------------ | ---------------------------------------- |
| 随机游走   | 打开几个 `httpd`/`cgi-bin` 就深挖，忘了看过什么                      | 强制 Phase 流水线 + 每阶段落盘                     |
| 覆盖不全   | 只看 `www/` 和 `bin/`，漏掉 `etc/init.d`、`.so`、内核模块、shell 脚本 | Phase 2 强制分层枚举 + **Phase 2.5 审阅清单三方对齐** + Phase 5 覆盖率门禁（100% 才放行） |
| 假装覆盖   | **声称审完了、实际只审了 70-85%**（长上下文里模型自己也记不清漏了哪个）        | Phase 2.5 审阅清单逐项打勾 + 门禁 diff「计划↔声明↔结论」 |
| 幻觉     | 编造不存在的函数名、伪造 `system()` 调用、凭印象写 CVE 号                  | 反幻觉铁律：每条结论必须带 `文件:偏移` + 原始证据片段           |
| 危险调用当漏洞 | 扫到 `system()`/`strcpy()` 就报 RCE/溢出                          | **漏洞成立条件四问**（代码存在/可达/可控/防护）+ `vuln-conditions.md` 判定树 |
| CVE 当漏洞 | 组件版本命中就写「设备存在 XX 漏洞」                                   | 铁律 7 + 门禁 CVE 纪律检查（V0-V3）                 |
| 深度不均   | 在静态图片上耗半天，放过 `upnpd` 的整数溢出                             | Tier 分层 + EALB 资源分配                      |
| 优先级不实  | CVSS 全给 9.8，需拆机的和 WAN 可达的排同一档                          | **DKTSS 评分**（减法模型，Friction 显式扣除利用阻力）      |
| 报告不可复现 | 每次格式不同、没有验证状态、缺字段                                  | 固定 **7 区块**模板 + **CONFIRMED/HYPOTHESIS 两态** + **9 字段必填校验** |

**核心思路**（迁移自大可实验室《AI 挖 Java 0day 不再靠运气》上篇的流水线设计 + 下篇的质量保障机制）：Skill 不教模型「什么是命令注入」，那是它已知的；Skill 给它装上**资深固件审计员的工作骨架**——定义流程、分配资源、设置护栏、标准化输出，并把中间状态持久化到文件系统，不信任模型的记忆。文章里的「6 阶段流水线 + EALOC 分层 + 三层审计架构 + 双轨模型」在固件场景下逐条对应为下面的 Phase 0-5、EALB、Layer 1-3 与 Track A/B/C（Track C 为固件专有的**跨请求污点**轨，见 Phase 3 Layer 2）；下篇的「覆盖矩阵、CONFIRMED/HYPOTHESIS、漏洞成立条件表、DKTSS、报告必填字段」对应为 Phase 2.5、`vuln-conditions.md`、`reporting.md` §3.1 与 `coverage_gate.py` 的机械化门禁。

## 三层架构：方法论 / 决策判据 / 原子能力

本 skill 固化的**不是「完整工具」，而是三层能力**。这个分层是刻意的——把一套完整决策流程固化成一个工具（FAT / Firmadyne / EMBA / FACT 的做法），遇到非常规固件就会在某一环卡死，剩下的只有依赖与兼容问题；而且它**在替 Agent 做决策**，而设备差异（SoC 是 ar71xx 还是 ipq40xx、文件系统是 squashfs 还是 UBIFS、内核是 4.14 还是 5.10、用户态是 BusyBox 还是完整 coreutils）恰恰决定了分析路径。

| 层 | 固化什么 | 承载位置 |
|---|---|---|
| **方法论层** | 决策逻辑、优先级、证据标准、降级策略、交付规范 | 本文件（七条铁律、Phase 0–5、EALB、三轨审计、G1–G7 门禁）· `references/methodology.md` · `references/reporting.md`（DKTSS / 7 区块） |
| **决策判据层** | **识别到什么特征 → 走哪条路**，以及失败反馈信号 | `references/atomic-capabilities.md` **§3**（Phase 1 提取选路树、Phase 4 仿真选路树） |
| **原子能力层** | **单个可调用的操作**：能力 / 实现方式 / 输入输出 | `references/atomic-capabilities.md` **§1–§9**（54 项原子能力：侦察、提取、内容扫描、文件系统侦察、二进制分析、动态验证、网络、硬件） |

**工作流是：侦察 → 按判据选路 → 调用原子能力 → 观察反馈 → 按反馈调整策略。**
不是「按顺序试工具」，更不是「调一个完整工具让它跑完」。**失败时先读反馈定位原因、针对性修补，换实现是最后手段。**

> 整链自动化工具（FAT / Firmadyne / EMBA / FACT / firmwalker）**只有一个合法位置**：主路径跑完后的**交叉验证基线**（`references/atomic-capabilities.md` §10.2），其输出按「线索」而非「结论」处理。它们不是 Phase 1/4 的主路径。

## 何时使用

使用：拿到固件镜像 / rootfs / 一堆嵌入式二进制，要做安全评估、漏洞挖掘、后门排查、渗透前置分析、SRC 众测前的自查。

不使用：纯 Web 应用源码审计（走代码审计流程）；纯硬件侧信道 / 电压毛刺（本 skill 只覆盖需要在固件里找软件漏洞的场景，硬件攻击面见 `references/resource-index.md` 的 Hardware Attacks 章节）。

## 前置：环境与授权

- **授权声明**：只在获得书面授权（自有设备 / 客户授权 / SRC 范围）的目标上执行。开工前把授权范围写进 `fw-audit/<target>/00-scope.md`。
- **环境**：各原子能力的实现（`unblob` / `binwalk` / `moria` / `mithril` / `Qiling` / `qemu-system-*` / `AFL++` / `radare2` 等）在 Linux（Docker / WSL / Kali / AttifyOS）下体验最好，**按 §3 判据按需安装，不必装齐**。Windows 宿主请优先用 Docker；本 skill 自带的全部 Python 脚本（`scripts/`）是**纯标准库**，任何平台都能跑。能力缺席时的替代实现见 `references/atomic-capabilities.md` §11。
- **容器化跑法定式**：
  ```bash
  docker run --rm -v "$PWD:/data" -w /data ghcr.io/onekey-sec/unblob:latest /data/firmware.bin
  ```
- **不要在宿主机直接运行目标固件里的二进制**，除非在模拟器 / 容器 / 专用虚拟机里。未隔离运行的固件可能主动出网或挂载真实设备。

### 本机工具基线（默认优先，非 GNU 对应物）

凡是**在自己的分析机上**遍历文件、搜内容、跑 Python，按此优先级；**不要默认用 `find` / `grep` / `pip`**：

| 场景 | 首选 | 缺失时降级 |
|---|---|---|
| 查找文件 | **`fd`**（Rust 重写 find） | `find` |
| 过滤内容 | **`rg`**（ripgrep） | `grep` |
| 结构化代码搜索 | **`sg`**（ast-grep） | `rg` + 正则 |
| Python 环境 | **`uv`**（`uv run` / `uv pip` / `uvx` 免安装直跑） | `venv` + `pip` |

降级要在报告里**显式注明**，不要静默替换。**边界**：这条只适用于本机——提取出的 rootfs 里跑的是**目标设备 busybox** 的 `grep`/`find`，不能换，也不能用 `--include` 等 GNU 扩展。详见 `references/atomic-capabilities.md` §1。

## 七条铁律

1. **证据优先**：每条 finding 必须附 `路径:行号/文件偏移` + 原文片段（反汇编、反编译、字符串、配置行）。写不出证据的结论一律降级为「疑点」，不得写成漏洞。
2. **空结果也是结果**：没找到就明确写 `NOT_FOUND` 并列出自查范围。禁止为了凑数编造漏洞、CVE 编号或 PoC。
3. **状态落盘**：所有中间结论写入 `fw-audit/<target>/` 文件，不依赖上下文记忆。任何阶段被打断都能从文件恢复。
4. **置信度只写两态**：对外只有 `CONFIRMED`（动态复现，或静态链路完整闭合且成立条件逐条验证通过）与 `HYPOTHESIS`（链路中断/条件未确认，**必须写明缺哪一步**）。`HYPOTHESIS` **不计入漏洞总数**。
5. **覆盖率门禁**：Phase 5 之前必须让分配清单里**每一个文件**都有审计结论。覆盖率 < 100% 不许出报告，先补审。**「我审完了」不算数——审阅清单要逐项打勾，门禁会 diff「计划 vs 声明 vs 结论」三方（Phase 2.5）。**
6. **凭据脱敏**：提取到的私钥、口令、云 token 在报告里只保留指纹（如 `SHA256:ab12…` 前 8 位）与位置，完整值单独写入 `50-secrets.local`（不进报告）。
7. **CVE 命中 ≠ 可利用漏洞**：`mithril --cve`（及任何 SBOM/版本比对）给出的是**「该组件这个版本在这个 CVE 的影响版本区间内」**，等价于一条**线索**，不是漏洞。必须回到 Phase 3/4 验证**可达性**后才允许升级措辞：

   | 状态 | 判据 | 允许的措辞 |
   |---|---|---|
   | `cve-hit` | 仅版本号落在影响区间 | 「**疑似**存在 CVE-XXXX-YYYY，**尚未验证可达性**」 |
   | `cve-reachable` | 已定位到调用该组件受影响函数的路径，且该路径在固件配置下可达 | 「存在 CVE-XXXX-YYYY，可达路径为…」 |
   | `cve-exploitable` | 动态复现或完整利用链 | 「可被利用」 |

   **禁止**把版本命中直接写成「设备存在 XX 漏洞 / 可被 XX 攻击」，禁止把 CVE 命中计入 P0/P1 数量（应单列「组件风险」节并标注未验证）。反例：某固件带 `busybox 1.31`（命中数十条 CVE），但该镜像编译时裁掉了相关 applet、或该版本已 backport 修复、或漏洞需要编译期未开启的选项——**版本在区间内但代码不存在，漏洞就不存在**。反之，版本号可能被厂商改过（`1.31` 实为带补丁的定制版），版本号本身也不可信。**结论只能来自对固件内实际代码的检查，不能来自版本号。**

## 流水线总览

工作目录约定（全程使用绝对路径）：

```
fw-audit/<target>/
├── 00-scope.md                   授权与边界
├── 00-metrics.json               Phase 0 度量结果
├── 01-extract/                  提取产物（rootfs 等）
├── 01-manifest.json             提取报告（chunk 偏移/类型/置信度）
├── 02-tiering.json              Tier 分层 + EALB 预算
├── 03-audit-plan.md             分配清单（谁审哪些文件）
├── 25-review-list.md            Phase 2.5 审阅清单（声明 + 逐项打勾）
├── 10-layer1-sinks.json         Layer 1 机器扫描结果
├── 20-findings-candidates.jsonl Layer 2 三轨候选（Track A/B/C）
├── 30-findings-verified.md      Layer 3 验证后结论（含 NOT_FOUND 台账）
├── taint-facts.json             跨请求污点事实（写/读端点，Track C 产物）
├── taint-graph.json             跨请求污点图（BDG + ADG，G7 的输入）
├── 40-coverage.md               覆盖率门禁报告
├── 50-rules/                    Phase 5 沉淀的 YARA / grep 规则
└── report.md                    最终报告
```

| Phase | 名称    | 输入            | 输出                                               | 主要原子能力                        |
| ----- | ----- | ------------- | ------------------------------------------------ | ----------------------------- |
| 0     | 度量与定界 | 固件镜像          | `00-metrics.json`、`00-scope.md`                  | `scripts/fw_triage.py`        |
| 1     | 提取与侦察 | 固件镜像          | `01-extract/`、`01-manifest.json`                 | 侦察（R1–R4）→ 判据选路（`atomic-capabilities.md` §3.1）→ 解包能力（E1–E9） |
| 2     | 分层与分配 | `01-extract/` | `02-tiering.json`、`03-audit-plan.md`             | `scripts/fw_triage.py --tier` |
| 2.5   | 覆盖矩阵与审阅清单 | `03-audit-plan.md` | `25-review-list.md`                            | 人工/模型声明 + 门禁 diff |
| 3     | 三层审计  | 分配清单          | `10-layer1-sinks.json`、`30-findings-verified.md` | `scripts/sink_scan.py` + 模型审计 |
| 4     | 动态验证  | 候选漏洞          | 每条候选的可利用性判定                                      | 仿真选路（§3.2）→ 原子能力组合（D1–D12）    |
| 5     | 门禁与报告 | 全部产物          | `40-coverage.md`、`report.md`、`50-rules/`         | `scripts/coverage_gate.py`    |

---

### Phase 0 · 度量与定界

目标：挖之前先知道**这是个什么东西、有多大、值不值得挖**。

```bash
uv run scripts/fw_triage.py <firmware.bin> --out fw-audit/<target>/00-metrics.json
```

脚本做这些事（纯标准库，不依赖 binwalk）：

- 文件级：大小、Shannon 熵、magic 猜测、是否压缩/加密包裹
- **分区块熵扫描**：定位压缩段 / 密文段 / 明文段边界
- 提取产物分析（给定 `01-extract/` 目录时）：文件数、按类型统计、ELF 架构直方图
- **ELF 加固画像**：纯 Python 解析 ELF 头 / 程序头 / 动态段 / 符号表，得出 NX、PIE、Canary、RELRO（Full/Partial）、FORTIFY，以及每个二进制的 `.text` 大小
- 权限面：SUID/SGID 文件、全局可写文件
- 攻击面清单：监听服务的可执行文件、`cgi-bin/*`、`*.cgi`、`www/`、`etc/init.d/*`、`rcS`、`rc.local`、`hotplug`、`*.sh`
- 敏感面：`/etc/passwd`、`/etc/shadow`、`*.pem`、`*.key`、`hostapd.conf`、`nvram`、`default.cfg`、`wpa_supplicant.conf`、`/etc/config/*`
- 打包痕迹：UPX / 自解压头 / 被抹零的 UPX 头

**产出判读**：如果熵扫描发现大片高于 7.9 的区域且无法提取，先判断是不是加密固件（走解密流程），不要硬审计乱码。

---

### Phase 1 · 提取与侦察

**先侦察，再决策。** 不要一上来就跑某个解包工具，也不要按固定顺序逐个试——**先拿到特征，再按判据直取对应的原子能力**。完整决策树（含每个分支的失败信号与回退条件）见 `references/atomic-capabilities.md` §3.1，此处给出主干：

```text
第 0 步（侦察，必做）：
  R1 file + magic bytes  →  容器类型
  R2 熵分布（binwalk -E / moria -E）→  高熵区在哪里、是否整体加密
  R3 头部与分区          →  各段起止、嵌套层级
  ↓
按识别结果分支（命中即取对应原子能力，不再往下试）：
├─ 熵 > 7.9 且无任何已知魔数、无文件系统候选   → E9 判为加密（不硬审乱码）
│    └ 先 R2 圈出高熵区边界 → 在内核/引导区找解密函数或密钥 → 解出后回到本条开头重跑
├─ SquashFS 魔数（hsqs / sqsh）               → E2 unsquashfs / moria -e
│    └ 解出为空或报 unsupported compression  → 换 sasquatch 版 unsquashfs，或 moria -e（多压缩后端）
├─ UBI# 头 / UBIFS 节点                       → E3 ubireader → 失败 → moria -e
├─ JFFS2 魔数（0x1985，注意大小端）            → E4 jefferson → 失败 → moria -e
├─ ext2/3/4 · F2FS · EROFS · cramfs · romfs   → E5 debugfs / dump.f2fs / fsck.erofs / cramfsck
├─ cpio / tar / gzip / xz / zstd 流           → E1 unblob 递归（当前层是中间层，继续下钻）
├─ uImage / FIT / ARM64 Image / zImage        → E6 切内核 → E7 取 DTB+bootargs → E8 恢复符号
└─ 完全无法识别                                → E1 unblob（carve + 78+ 格式）
     └ 仍拿不到文件系统 → 记 manifest + warning，转人工 hexdump；不要用「兜底工具」糊过去
```

每次尝试的**判据、选了哪条路、为什么**都要记进 `01-manifest.json` 的 `extraction` 段（字段里同时写能力编号与实现名，见下）。

**「失败」的判定 = 两级门，看「有没有拿到可用文件系统」，不看退出码。** 退出码 ≠ 0 但提取出了完整 rootfs → **成功**（只记 warning）；退出码 0 但只 carve 出裸块 → **失败**（必须换路）。这一条是为了杜绝「乱换路」：

| 级 | 判据（任一命中即失败） |
|---|---|
| **L1 进程级** | ① 命令不存在（`command -v` 失败）② 退出码 ≠ 0 **且** 输出目录为空/未创建 ③ 超时被杀 / OOM（>15 min 无新产物） |
| **L2 产物级（决定性）** | ④ manifest 空或 0 个 chunk ⑤ **未产出任何可识别文件系统**（只有 carve 出的裸文件/压缩流，没有 SquashFS/ext/JFFS2/UBIFS/CRAMFS/cpio 目录）⑥ 识别到文件系统 chunk 但标记 `unhandled`/`error`（典型：**缺 `sasquatch` → SquashFS 静默为空**） |

**「可用文件系统」的客观定义**（三条同时满足才算有效产物，缺一即换路）：

```
rootfs_ok := 存在目录 D，满足
  (a) D 下有 {bin|usr|etc|lib} 中至少 2 个；
  (b) D 下 ELF 文件数 ≥ 1，或 shell 脚本数 ≥ 1；
  (c) D 下有 bin/sh、bin/busybox、etc/init.d/ 三者之一。
```

若走 E1（unblob）实现，先跑 `unblob --show-external-dependencies` 确认外部解包器就绪——缺解包器正是 L2-⑥ 的高发原因。

**反向判据（不要误换路）**：退出码 0 且拿到合规 rootfs，只是个别未知块/边角文件没解 → 记 `warning`，**不换路**；把未解块路径记进 manifest 供后续手撸。**换路不丢弃上一级产物**——carve 出的块、内核、DTB 全部保留并合并进 `01-extract/`。

**全部路径都拿不到文件系统**：高熵 + 无任何文件系统 → 判为**加密固件**，走解密（找密钥/解密函数）后**回到 Phase 1 侦察步重新入链**，不要硬审乱码。每次决策都要留痕，便于复盘「为什么走了这条路」：

```json
"extraction": {"attempts": [
  {"capability": "E1", "impl": "unblob",  "verdict": "fail", "reason": "L2-⑥ squashfs chunk unhandled (sasquatch missing)", "out": "01-extract.unblob"},
  {"capability": "E2", "impl": "binwalk", "verdict": "fail", "reason": "L2-⑤ carved blobs only, no filesystem",        "out": "01-extract.binwalk"},
  {"capability": "E2", "impl": "moria",   "verdict": "ok",   "reason": "squashfs 2547 files; bin/busybox + etc/init.d present", "out": "01-extract"}
]}
```

示例（侦察 → 判据 → 原子能力）：

```bash
# 第 0 步：侦察（R1–R3）——先看清是什么，再动手解
file firmware.bin
binwalk firmware.bin                                   # R1/R3 仅识别
binwalk -E firmware.bin                                # R2 熵分布，判断是否有加密区
moria -j firmware.bin > moria-findings.json            # R1/R2/R3 一起给（偏移+类型+置信度）
moria -E firmware.bin                                  # R2 孤立高熵区（疑似加密/压缩）

# 命中 squashfs 分支（E2）
moria -e firmware.bin -C fw-audit/<target>/01-extract
# 或 unsquashfs -d rootfs <按 R3 偏移切出的 squashfs 镜像>

# 命中 UBI/UBIFS 分支（E3）
ubireader_extract_images firmware.bin -o 01-extract/ubi
# 命中 JFFS2 分支（E4）
jefferson -d 01-extract/jffs2 <按 R3 偏移切出的 jffs2 分区>

# 命中内核分支（E6→E7→E8）
binwalk -e firmware.bin                                 # 或按偏移 dd 切
dtc -I dtb -O dts -o kernel.dts <提取出的 dtb>          # E7 取 bootargs/分区布局
vmlinux-to-elf vmlinux vmlinux.sym                      # E8 恢复符号，后续 nm/objdump 可用

# 完全无法识别时（E1 兜底）
unblob --report 01-manifest.json -e fw-audit/<target>/01-extract firmware.bin
```

提取完立刻做**内容级扫描**（moria 管「字节在哪」，mithril 管「里面写了什么」）：

```bash
mithril --fetch-db            # 仅首次：拉本地 CVE 镜像（唯一联网命令）
mithril -j fw-audit/<target>/01-extract > mithril.json
mithril --secrets <dir>       # 凭据 / 密钥 / JWT / hash
mithril --sbom -C out/ <dir>  # CycloneDX + SPDX
mithril --cve <dir>           # 组件 CVE（本地镜像、离线、带 CISA KEV 与 EPSS）
mithril --boot <dir>          # U-Boot env / device tree / FIT-AVB / UEFI Secure Boot
mithril --keys <dir>          # 泄露或默认公钥、ROCA、弱 RSA、可因式分解公钥
```

> ⚠️ **`--cve` 的输出是线索，不是漏洞。** 它只回答「组件版本是否落在 CVE 影响区间」——**不回答「这段代码是否真的存在于固件里、是否可达」**。所有 `--cve` 命中一律先记为 `cve-hit`，写入 `20-findings-candidates.jsonl` 时 `track="component"`、`confidence="candidate"`，**必须**在 Phase 3/4 补做可达性验证（见铁律 7）后才能改措辞或计入漏洞数。禁止把它直接列进「漏洞」章节。

**能力缺席时不要换路去装整链工具。** 缺哪个原子能力，优先按 `references/atomic-capabilities.md` §11 找等价实现（如 C1–C3 缺 mithril → `firmwalker` + 自写 `rg` 规则，但 CVE 结果的可信度下降、三问复核要更严）。`FAT` / `EMBA` / `FACT` 只在主路径跑完后作**交叉验证基线**（§10.2），不作为替代路径，其输出按线索处理。

提取后必做四件事，缺一不可（本机命令用 `fd`/`rg`，见 `references/atomic-capabilities.md` §1）：

1. `fd -t f -x file {}` → 建立类型清单（替代 `find . -type f -exec file {} +`）
2. `fd -t f -x sh -c 'test -u "$1" -o -g "$1" && echo "$1"' _ {}` → SUID/SGID
3. 读启动链：`etc/init.d/*`、`etc/rc.d/*`、`inittab`、`rcS`、`rc.local`、`hotplug`、`/etc/config/*` —— **启动链就是攻击面地图**，它告诉你哪些服务真正在跑
4. **枚举「动作关键字」（action keyword）**：从 Web 前端（`web/*.js`、`*.htm`、ASP 指令、XHR 参数）与脚本里抽出请求动作名——`rg -o -N '"[A-Z][A-Za-z0-9_]{3,}"' web/ | sort -u`——连同它落在哪个入口文件/二进制。这是 Phase 3 **Track C 构建动作依赖图（ADG）**的种子：**只看单个请求会系统性漏掉「请求 1 写、请求 2 读」的高阶漏洞**（见 Phase 3 Track C 与 `references/methodology.md` §3.2）。

> ⚠️ 区分「本机工具」与「目标环境工具」：上面第 1、2 步是在**我的分析机上**遍历提取产物，用 `fd`；但若把命令放进 rootfs 内执行（chroot / 模拟环境），那是**目标 busybox** 的 `find`，不能换、也不能用 `--include` 等 GNU 扩展。带 `-perm` 的判断尤其要在本机做（Windows 上 `fd`/`fd -x test -u` 的权限位不可靠，此时改用 `fw_triage.py` 的 `permission_scan_reliable` 字段）。

---

### Phase 2 · 分层与分配（EALB）

固件里 60-80% 的字节不值得深挖（静态资源、locale、证书、字体、第三方库）。按文件数平均分配会严重浪费预算，但也不能跳过——静态资源里偶尔藏着硬编码 token 或调试页面。

#### Tier 分层规则

规则**从上到下**匹配，先命中先定级：

| 规则 | 条件 | 结果 |
|---|---|---|
| R0 | `doc/` `man/` `locale/` `zoneinfo/` `licenses/` `fonts/` `terminfo/`、图片与字体扩展名（`*.png` / `*.jpg` / `*.svg` / `*.woff` / `*.ttf`）、发行版包元数据 | **SKIP**（仅做关键字扫描，不做语义审计） |
| R1 | Layer 1 预扫描命中 P0/P1 候选 | **T1**（动态提升，不论原级别） |
| R2 | 外部输入入口：监听服务可执行文件、`cgi-bin/*`、`*.cgi`、web handler、`upnpd` / `httpd` / `telnetd` / `sshd` / `dnsmasq` / `mosquitto` / `smbd` / `ftpd`、协议解析器 | **T1** |
| R3 | 启动与配置：`etc/init.d/*`、`rcS`、`rc.local`、`inittab`、`hotplug`、`*.sh`、`/etc/config/*`、`*.conf`、`nvram` 默认值 | **T1** |
| R4 | 共享库 / 内核模块 / 非监听守护进程 / 工具类：`*.so*`、`*.ko`、`usr/libexec/*` | **T2** |
| R5 | 未匹配任何规则 | **T2**（保守兜底，**不降级**） |
| R6 | 静态资源、文档、纯数据：`www/` 下的 html/css、非 vendor 的前端 JS、`*.xml` 数据 | **T3** |
| R7 | T3 文件命中 P2/P3 候选 | 保持 T3 但标 `review_flag=true`（升为快速人工复核） |

R5 的「保守兜底」是刻意的：未识别文件的默认级别是 T2 而非 T3，宁可多花预算，不降低分析深度。
规则以 `assets/tier-rules.json` 为准；实现上**兜底规则永远最后评估**（先跑完所有具体规则，仍未命中的才落到 R5），因此 R6 的静态资源不会被兜底抢走。

#### EALB 公式

```
EALB = Σ ( tier_weight(f) × text_KB(f) )
       T1 = 1.0    T2 = 0.5    T3 = 0.1
```

`text_KB` 取 ELF 的 `.text` 段大小（不是文件大小——一个 2MB 的二进制可能只有 180KB 代码）。shell 脚本与配置文件按行数折算 KB。

```
Agent 数 = ceil(EALB / 800)      # 单 Agent 预算 800 EALB 单位，可按上下文窗口调整
```

> **当前是启发式，不是已验证预测**：`assets/ealb-calibration.json` 的 `status` 为 `heuristic`（真实样本 0），EALB 只用于**相对排序与切分 Agent**，不得写成工期承诺。用 `scripts/ealb_calib.py` 记录 `ealb` 与实际工时；真实样本 ≥20 进 `experimental`，≥60 且 MAPE ≤0.30 才进 `calibrated`。

**效果示例**（真实形态的 IPC 固件）：T1 3.2MB 代码 + T2 8.4MB + T3 22MB →
  
`EALB = 3200 + 4200 + 2200 = 9600` → 12 个 Agent。
  
若按原始字节平均分：`(3.2+8.4+22)MB / 800KB ≈ 43` 个 Agent。**省下 72% 预算，深度不降。**

```bash
uv run scripts/fw_triage.py --rootfs fw-audit/<target>/01-extract \
    --tier --budget 800 \
    --out  fw-audit/<target>/02-tiering.json \
    --plan fw-audit/<target>/03-audit-plan.md
```

`--rootfs` 是路径参数、`--tier` 是布尔开关、`--plan` 才会写出计划文件——三者缺一个都拿不到预期的 `03-audit-plan.md`。

产出 `03-audit-plan.md`：每个 Agent 分到的文件清单（绝对路径 + Tier + text_KB），一条一行，便于逐项打勾。

---

### Phase 2.5 · 覆盖矩阵与审阅清单（反「声称 100% 实际漏审」）

**为什么单列一个 Phase**：多 Agent 长上下文下最常见的失败不是「找不到漏洞」，而是**模型声称审完了、实际只审了 70-85%**。写不出覆盖矩阵，就不许进 Phase 3。

产出两份东西：

**① 审阅清单（`25-review-list.md`）——「我打算看哪些文件」的显式声明**

按分片列出本轮要读的每个文件，用 markdown 复选框，**读到即打勾**：

```markdown
## S01 · httpd 分片（Agent A）
- [x] `usr/sbin/httpd`
- [x] `usr/lib/libnvram.so`
- [ ] `usr/lib/libcrypto.so.1.1`
```

**② 文件级审计台账（`30-findings-verified.md` 的标题即台账）**

每个文件**必须有且只有一条**结论：`## F-xxx`（发现）或 `## NOT_FOUND · <file>`（已审无果）。空着 = 没审。

**三方对齐（门禁自动做）**：`03-audit-plan.md`（计划要审的）↔ `25-review-list.md`（声明要审的、实际打勾的）↔ `30-findings-verified.md`（有结论的）。三者不一致即阻断，缺口分三类：

| 缺口 | 含义 | 提示的问题 |
|---|---|---|
| **G1 声明未勾选** | 清单里 `[ ]` 没打钩 | 声明了却没审——最常见的「假装覆盖」 |
| **G2 计划未声明** | 计划要求审的 T1/T2 文件没进清单 | 悄悄缩小了范围 |
| **G3 勾选无结论** | 打了钩但无对应 finding/NOT_FOUND | 读了但没落结论（注意力丢失） |

门禁命令（`--review-list` 触发三方 diff）：

```bash
uv run scripts/coverage_gate.py \
    --plan fw-audit/<target>/03-audit-plan.md \
    --verified fw-audit/<target>/30-findings-verified.md \
    --review-list fw-audit/<target>/25-review-list.md \
    --tiering fw-audit/<target>/02-tiering.json \
    --out fw-audit/<target>/40-coverage.md
```

**检出缺口后的修复路径（自动 vs 人工，必须显式区分）**

检出 G1/G2/G3 只是第一步；**能不能自动补齐，取决于缺口的性质**——不是一律人工，也不是一律自动：

| 缺口 | 性质 | 自动修复？ | 动作 |
|---|---|---|---|
| **G1 声明未勾选** | 已规划、没执行完 | ✅ **自动** | 把缺失文件重派给原 shard；原 Agent 已结束则新起「补审」Agent，只带该文件 + Layer 1 摘要 + 所属 shard 上下文，补审后写结论并打勾 |
| **G3 勾选无结论** | 已读、没落结论 | ✅ **自动（限 1 轮）** | 触发「结论汇总」重跑：把该文件已产出的内容整理为 `## F-xxx` 或 `## NOT_FOUND · <file>`；**重跑仍无结论 → 升级人工** |
| **G2 计划未声明** | 范围被悄悄缩小 | ❌ **禁止自动** | 只能二选一：**(a)** 生成「补充分片」把文件补进清单并重审；**(b)** 写 **waiver** 豁免（含理由 + 责任人 + 影响面）。**禁止静默塞回清单** |

**五条硬规则**：

1. **自动修复的边界 = 不得改变「审什么」的范围。** G1/G3 属「已规划未执行完」→ 可自动补执行；G2 属**范围决策** → 必须人工留痕。
2. **自动修复不得静默。** 每轮写入 `40-coverage.md` 的 `auto_recovered` 段（缺口类型 / 文件 / 轮次 / 结果）；**缺口一旦出现过就永久留痕**，不能「修完即消失」。
3. **轮次上限 2 轮。** 第 3 轮仍有缺口 → 强制人工，门禁直接阻断。
4. **自动修复只补产物，不编结论。** 结论仍由人/模型基于证据写，机器不得替它生成 finding。
5. **G2 走 waiver 的，waiver 必须出现在最终报告「未覆盖项 + 理由」里。**

> **实现现状**：`coverage_gate.py --auto-recover` **已实现「出计划」，不实现「代执行」**——它按上面的边界把缺口转成 `40-coverage.auto-recover.json`（缺口类型 / 文件 / 轮次 / 是否超限），并在 `40-coverage.md` 写 `auto_recovered` 段留痕；**真正重派 shard、重跑补审仍由编排方（Agent）执行**，脚本不替它改产物、更不替它编结论。`--recover-round N` 与 `--max-rounds 2` 控制轮次，超限即回硬门禁。详见 `references/methodology.md` §5.1.1。

---

### Phase 3 · 三层审计架构

#### Layer 1 —— 机器扫广度（不使用 LLM）

```bash
uv run scripts/sink_scan.py fw-audit/<target>/01-extract \
    --rules assets/sink-rules.json --json fw-audit/<target>/10-layer1-sinks.json
```

规则库覆盖 C/C++ 内存与命令执行、shell 脚本、CGI/PHP/前端 JS 三类语言，按 P0-P3 分级：

- **P0**：命令执行（`system`/`popen`/`execve`/CGI 里的反引号）、无边界拷贝（`strcpy`/`sprintf`/`strcat`/`memcpy`）、格式化字符串、`/dev/mem`·`mtd` 裸写、`insmod`/`modprobe`、反序列化
- **P1**：认证/鉴权缺失线索、OTA 升级无签名校验、`SSL_VERIFY_NONE`、明文口令比较、固定 salt、调试 shell 入口
- **P2**：弱随机（`rand()`/`srand(time)`）、硬编码密钥、调试开关、`chmod 777`、日志注入面
- **P3**：信息泄露面（版本串、内部 IP、被注释掉的凭据）

排噪规则（必须生效，否则规则库会被噪声淹没）：跳过 R0 目录；二进制文件里只报「字符串命中」不报「代码命中」（代码层交给 Layer 3 反汇编）；同一文件同一规则只报首个命中并给出计数；跳过 import/注释行。

**扫描完整性（`scan_integrity`）**：二进制按 `--read-chunk-mb`（默认 4 MiB）分块流式读取，跨块边界的字符串用 carry 缓冲拼接，**不会因为分块而漏检**；文本超过 `--max-lines`（默认 40 万行）或文件超过 `--max-file-mb`（默认 96 MB）时会如实标记。输出里的四类跳过原因必须分开看：`skip-dir`（设计如此）/ `excluded`（调用方排除）/ `too-large`（能力边界）/ `stat-failed`（异常）。**`complete: false` 时报告里不得写「已完整扫描」**，把 `scan_integrity` 贴进附录即可——这是「扫描了什么、哪些没扫」的唯一可信来源。

**脚本 / web 目标的二次过滤（可选增强）**：正则在脚本类目标上分不清「代码」与「注释/字符串」——`# eval "$x"`、`echo "system(id)"`、`// system($x)` 都会误报。对 P0/P1 的 script/web 规则，`sink-rules.json` 里带 `structural` 字段的会用 `ast-grep` 在**正则已命中的文件上**做结构确认：结构否定即判为误报丢弃；引擎缺失或语言不可判则**自动回退正则并记录进 `engine_status.fallbacks`**。判据与铁律见 `references/atomic-capabilities.md` §3.3，实现见 §5.2。三条要点：**① 只作二次过滤、不作候选生成器；② 对剥离符号的 ELF 不适用；③ 不要把反编译伪代码喂给它**（IDA 伪代码不是合法 C，解析器会产垃圾 AST）。

**Layer 1 的定位是辅助参考，不是唯一入口。** 模型必须逐文件阅读分给它的全部代码，Layer 1 只负责告诉它「这里已知有危险形态，优先验证」。只看工具标记的文件，会系统性漏掉逻辑漏洞——认证绕过、状态机缺陷、签名校验缺失这类「本该有却没有」的问题，工具看不见。

#### Layer 2 —— 三轨审计（模型主场）

每个 Agent 对分到的文件跑**三条并行轨道**，按 Tier 决定深度。Track A/B 处理**单个请求内**的数据流与控制流；Track C 专攻**跨请求**的持久化污点——固件里最高频、也最容易被单请求视角漏掉的一类（高阶漏洞）。

**Track A · Sink-driven（自下而上）**：从危险调用点往上追数据来源。

```
strcpy(dst, user_buf) → user_buf 来自哪？ → recv() 的 socket？
                      → 谁调这个函数？ → socket 是否需认证？ → 长度是否校验？ → 可越界上限？
```

职责：发现「危险代码的存在」。

**Track B · Control-driven（自上而下）**：从入口点往下查「该有的安全控制有没有」。

```
枚举入口：/cgi-bin/xxx、SOAP action、UDP 1900、TCP 80/443/8080/23/22、MQTT topic
逐项问：认证？授权（越权/IDOR）？CSRF？输入校验？输出编码？
        固件升级是否验签？TLS 是否校验证书？命令是否走白名单？是否可触达 sink？
```

职责：发现「安全控制的缺失」。**认证绕过、OTA 无验签、越权改配置只能用 Track B 找到**——它们不是「某行代码有问题」，而是「某个入口缺了应有的检查」。

**Track C · Cross-request-driven（跨请求 / 状态机）**：污点的写入与触发跨请求、跨进程，经**持久化存储**传递。

```
请求1: SetNetwork → nvram_safe_set("lan0_management_link", <用户可控>)   ← 写面
请求2: SetVLAN    → notify_rc("start_vlanall") → rc 进程 → nvram_safe_get(...) → system()  ← 读面 + sink
```

职责：发现「单请求视角看不到的高阶污点漏洞」。**Track A 追的同请求 source→sink 在这里是断的**——httpd 读 `wan_ifname` 时，同一请求内根本没有它的写入点（RAXE500 `F-012` 就是这样被漏掉的：`wan_ifname` 在 httpd 内 20 处引用**全为读、零写**，真正的写面在上传恢复配置那条链路）。方法源自 Bridge（IEEE S&P'26），完整算法与阈值见 **`references/high-order-taint.md`**。

**持久化存储的 4 类**（都可能成为跨请求污点通道）：

| 类 | 载体 | 写 API（写面） | 读 API（读面） |
|---|---|---|---|
| NVRAM | nvram / uci 键 | `nvram_set`·`nvram_safe_set`·`acosNvramConfig_set`·**恢复配置导入** | `nvram_get`·`acosNvramConfig_get/match` |
| 文件 | `/tmp`·`/var`·`/etc`（含符号链接）| `fopen+fwrite`·`echo >`·上传落盘 | `fopen+fgets`·`source`·`tar -C /` |
| IPC | socket / 控制消息 | `sendto`·`notify_rc`·`ubus` | `recvfrom`·`recvmsg` |
| 环境 | 进程环境 | `setenv`·`putenv` | `getenv` |

**Track C 三步**：

1. **枚举写面**：Layer 1 的 `cross-request` 规则（`sink-rules.json` 的 `P1-T-001/002`、`P2-T-001/002`）已标出所有「持久化写入」点；记下键名 / 路径与值的可控性。
2. **配对读面**：对每个写面，全量检索谁**读**了同一键 / 路径并送入 sink。**写入与读取常分属不同请求、不同进程**——这正是单请求 Track A 追不到的原因。
3. **闭合溯源**：证明 sink 拿到的值由攻击者**可控地**写入——写面本身是否需认证？是否有键名白名单？（**无白名单的「恢复配置导入」= 任意键可控**，见 RAXE500 `F-012`/`F-013`。）

**把三步做成图（不是写成段落）**——报告里「由恢复配置导入」这种表述无法被复核，必须落成五元组：

```
write.action --key--> 存储 --key--> read.trigger_action
                                    └─ via(控制值) → read.binary:addr → sink
```

`read.trigger_action` 是**前端发起、最终导致该次读取的 action**；`read.binary:addr` 是**真正执行读取的进程与地址**。两者不同：读点几乎总在 `rc`/`librcm.so`，只用后者会把一阶全部冒充成高阶（DIR878 实测：`SysLogRemote_IPAddress` 读在 `rc`，但写与触发同为 `SetSysLogSettings` → 一阶）。

```bash
# ① 从反编译产物恢复常量键（literal / local-const / fill-composed；拼不出来记 unknown）
uv run scripts/taint_graph.py recover --src fw-audit/<t>/decomp \
    --out fw-audit/<t>/taint-facts.json --target <t>
# ② 补齐读写点、触发 action、via_control 与 sink 后构图，并自检 C1–C5
uv run scripts/taint_graph.py build --facts fw-audit/<t>/taint-facts.json \
    --out fw-audit/<t>/taint-graph.json --md fw-audit/<t>/taint-graph.md --strict
```

判据五条，每条都能否决结论：**①写它的请求 ≠ 触发读的请求**（同一请求 = 一阶，不许算高阶）；②键在两端字面一致；③读面到 sink 真实可达；④两端都有地址与证据；⑤读点在别的进程时必须给 `via_control`（哪个控制值把请求带过去），否则「能到达」只是假设。方法全貌（AEH 三形态与阈值、BDG 两段污点、OD-ICP 常量恢复、控制消息双约束、ADG 三类控制依赖、欠约束符号执行参数、**DIR878 实测复现**）见 **`references/high-order-taint.md`**；IPC 原语词表见 **`assets/ipc-functions.json`**。

> ⚠️ **门禁挂钩（G6 + G7）**：G6 查**报告文字**——finding 的 `Source` 指向运行时写入的持久化存储时，必须声明**写入面**（`--cross-request`）。G7 查**图**——`--taint-graph` 校验上面五条判据；strict 档位下，报告一旦声称存在高阶漏洞，**没有图就直接失败**（只有结论没有链 = 不可复核）。
>
> ⚠️ **静态枚举的边界**：控制消息关键字可能被 `str_merge`/`snprintf` **动态拼接**（如 `"lan0_" + "management_link"`），纯字符串匹配会漏——必须回溯拼接点。`taint_graph.py recover` 能覆盖「字面量 / 局部常量 / 缓冲区填充」三种，覆盖不了的**必须显式记 unknown**，不能用占位键蒙混（Bridge 用欠约束符号执行补这一段，代价是 600 s/键）。


**按 Tier 的深度**：

| Tier | 深度      | 具体动作                                                                                                       |
| ---- | ------- | ---------------------------------------------------------------------------------------------------------- |
| T1   | 全量 8 项  | ①入口枚举 ②数据流 ③安全控制逐项核查 ④敏感操作（文件/网络/加密/序列化/`insmod`/`ioctl`）⑤自定义封装库是否包了危险操作 ⑥配置与初始化 ⑦业务逻辑（状态机/竞态/条件判断）⑧绕过假设穷举（B1–B12 清单，见 `references/methodology.md` §3.1） |
| T2   | 3 项     | 数据流 + 敏感操作 + 安全控制                                                                                          |
| T3   | 3 项模式匹配 | 硬编码凭据 / 调试接口 / 危险字符串                                                                                       |

**动态提升**：T2 文件里发现封装了危险操作 → 就地按 T1 分析；T3 文件里发现业务逻辑 → 提升到 T2。每次提升写进 `02-tiering.json` 的 `promotions` 数组，便于复盘。

**⑧ 绕过假设穷举（T1 必做，最易被跳过的一项）**

原则：**「有防护」不等于「防护有效」。** 凡是 Track B 判定某入口「已有防护」（有鉴权 / 有白名单 / 有长度校验 / 有验签 / 有路径过滤），**不得就此记「安全」或 NOT_FOUND**——必须对该入口逐条跑 B1–B12 绕过清单，每条结论三选一：

- `N/A`（该类型不适用于此入口，写明理由）
- `已测·不可绕过`（附**具体证据**：哪行比较、哪个过滤、实测输入）
- `可绕过` → **升级为 finding**，走 Layer 3 追链

| # | 绕过面 | 固件场景怎么测 |
|---|---|---|
| B1 | **空口令 / 缺省口令** | 口令字段缺失 vs 为空串；`strcmp(pw, "")==0`；认证函数早返回；直接置位绕过登录 |
| B2 | **默认 / 硬编码凭证** | `default_passwd`、`super_password`、后门账号；常量串比对（非哈希）；厂商通用口令可猜 |
| B3 | **认证覆盖缺口** | 免鉴权白名单（`no_auth`/`skip_auth`）覆盖了敏感路由；**HTTP 方法差异**（GET 免鉴权、POST 鉴权）；后缀/前缀豁免 |
| B4 | **前缀匹配绕过（startswith/strstr）** | `strncmp(path,"/cgi-bin/",9)` 能否被 `/cgi-bin/..%2f`、`/cgi-bin/x/../../`、`/cgi-bin/` 后带 `?`/`#` 骗过 |
| B5 | **路径穿越变形** | `../`、`..\`、`%2e%2e%2f`、`..%c0%af`、双重编码、绝对路径、尾随点/空格、长路径截断、软链接 |
| B6 | **大小写 / 编码 / 规范化** | 比较不区分大小写但 FS 区分；UTF-8 overlong；`%00` 截断；Unicode 归一化后不等 |
| B7 | **参数污染（HPP）** | 校验取**第一个**同名参数、使用取**最后一个**；数组参数；「缺值」与「空值」分支不同 |
| B8 | **边界 / 截断** | `>` vs `>=` 差一；有符号/无符号；`strncpy` 不补 `\0`；`strlen` 后长度被改；整数溢出绕过上限 |
| B9 | **白名单命令注入** | 白名单「有」但可被 `;` `&&` `\|` 换行 `` ` `` `$()` 注入；参数位注入（`-o`、空格/引号逃逸）；元字符编码 |
| B10 | **时间窗口 / 竞态（TOCTOU）** | 校验路径 vs 打开路径不一致；检查后被替换；令牌验证后被改；并发请求绕过一次性检查 |
| B11 | **状态 / 顺序绕行** | 未初始化状态被信任；跳过前置步骤直调后置接口；重放；恢复出厂后残留下发 |
| B12 | **校验对象 ≠ 使用对象** | 校验 `Host` 却信 `X-Forwarded-Host`；校验前端文件名后端用另一字段；验签 A 却加载 B；查一个 header 却信任另一个 |

产出：每个入口一张 `bypass_matrix` —— `{入口, 已存在的防护, B1..B12 结论, 升级出的 finding_id}`，随该文件的结论一起写入 `30-findings-verified.md`。

候选结果逐行写入 `20-findings-candidates.jsonl`：

```json
{"id":"F-001","file":"usr/sbin/httpd","offset":"0x2a14","tier":"T1","track":"sink",
 "sink":"strcpy@0x2a30","source_hypothesis":"HTTP Referer header","rule":"P0-C-002",
 "evidence":"strings: 'Referer: %s' @0x1c40; disasm: strcpy r0,r1 @0x2a30",
 "confidence":"candidate","needs":"需确认 len 上限"}
```

#### Layer 3 —— 语义级链路验证

Layer 2 的候选必须验证 **Source→Sink 可达性**。按「有没有 MCP」分两条路，**都要走**，MCP 只是把手工路自动化了。

> **跨请求候选必须补做「反向来源追溯」**（Track C 候选专属）：当 `Source` 来自持久化存储（nvram / 文件 / IPC），Layer 3 的验证不止「**本请求内** source→sink 闭合」，还要**反向**回答「这个值是谁写进来的、什么时候写、是否可控」。对每个此类 sink 维护一条**污点来源历史** `store → 写面(入口/请求) → 读面(sink)`；写面缺失即只能是 `HYPOTHESIS`（= G6 fail）。RAXE500 的做法可参照：先用全量 xrefs 证明 `wan_ifname` 在 httpd 内**只读**，再据此把唯一写面锁定到「恢复配置导入」，从而闭合溯源。

**路径 A：二进制逆向 MCP（有则必用，命中率与效率最高）**

| MCP | 前置 | 能力 |
|---|---|---|
| **IDA Pro + `ida-mcp`**（官方，HexRaysSA/ida-mcp） | IDA **9.4+**（含 idalib）+ Python 3.11+ | 反编译伪代码、交叉引用、动态执行 IDAPython——**给模型的是真语义，不是字符串猜谜** |
| **`pyghidra-mcp`** | Ghidra + JDK | 无头 Ghidra 反编译结果查询（免费路线） |

`ida-mcp` 只暴露 6 个工具（`open_database` / `execute_python` / `reference` / `list_databases` / `save_database` / `close_database`），**真正的能力在 `execute_python`**：模型写 IDAPython/`ida-domain` 代码在 IDA 进程内跑，直接拿反编译文本和 xref。典型链路：

```python
# execute_python 里跑（ida-domain API，IDA 9.1+；底层是 ida_nexus）
db = ...                                    # ida_mcp 已 open 的库
f = db.functions.get_at(0x2a30)             # 定位函数
print(db.functions.get_pseudocode(f).to_text())      # 伪代码（真语义）
for x in db.xrefs.to_ea(0x1c40):            # 谁引用了这个字符串地址
    print(hex(x.from_ea), x.type.name)      # → 调用点 → 回溯到 HTTP 处理函数
db.functions.get_disassembly(f)             # 反汇编
db.bytes.find_text_between('ping')          # 字符串/字节搜索
```

用它的理由：固件里高频的「字符串锚点 → 引用点 → 调用者」三跳手工追链，在 MCP 下变成一条 xref 查询。**但注意**：MCP 给出的是反编译器的*推断*（变量类型、函数边界都可能错），**证据仍是反汇编/字节，不是伪代码**——伪代码只能用于理解控制流，不能直接当 finding 的原文证据引用。

配置（写进**你所用 Agent 的 MCP 配置文件**——形如 `~/.<agent>/mcp.json`——的 `mcpServers`，改完需在连接器管理页点「信任」才生效）：

```json
{"mcpServers": {"ida": {"command": "uvx",
  "args": ["--exclude-newer=1s", "ida-mcp", "stdio"]}}}
```

> `stdio` 子命令另有一个**可选**参数 `--agent <名称>`，官方说明是 "Agent name to record in the MCP session trace"——只写进会话跟踪元数据，不参与任何鉴权或功能开关，**可省略**，填任意名称也可。

**MCP 的硬前置与坑**：需 IDA 9.4+ 与 idalib 授权（商业授权，**没有就退回路径 B**）；`execute_python` 默认 `flush_database=True` 会立刻写 `.id0/.id1`，**对固件二进制是写操作**——先在副本上跑；一条命令超时（默认 360s）只是「请求中断」，阻塞型 `sleep()` 可能仍在跑；失败**不自动重试**（可能已改库）。

**路径 B：无 MCP 时的替代实现链（任何环境都必须能跑）**

```bash
# 1) 反汇编 / 交叉引用（radare2，可脚本化，最通用）
r2 -A -q -c 'aaa; axt @ sym.imp.strcpy' usr/sbin/httpd
r2 -A -q -c 'afl~cgi; s main; pdf' usr/sbin/httpd

# 2) 反编译（Ghidra 无头，批量，免费路线的语义级）
analyzeHeadless /tmp/ghidra_proj fw -import usr/sbin/httpd -postScript DumpDecomp.java

# 3) 永远可用的交叉验证：binutils（输出本机过滤用 rg）
readelf -d usr/sbin/httpd | rg 'NEEDED|BIND_NOW|FLAGS'
objdump -d -M intel usr/sbin/httpd | rg -n -A20 '<main>'
nm -D --undefined-only usr/sbin/httpd | rg 'system|popen|strcpy|memcpy'
strings -a -t x usr/sbin/httpd | rg -i 'referer|cmd|ping|traceroute'

# 4) 符号剥离时的兜底：字符串锚点 → 引用点 → 回溯调用者
```

每一跳都必须记录 `文件:偏移`，形成完整调用链。**反汇编不可用/失败时**（固件被加密后解出畸形结构、工具缺失、架构不支持）降级为 `rg + strings + objdump` 手工追链，并在报告标注「静态链路，未经反汇编确认」——精度下降但流程不中断。

三条路径的取舍：**MCP 反编译（真语义）> Ghidra 无头（批量语义）> radare2 手工追链（可行但慢）> objdump+strings（兜底）**。无论走哪条，**证据等级不打折**——区别只在成本，不在结论强度。


验证结果写入 `30-findings-verified.md`，每条带：
`ID / 标题 / 类型 / 文件:偏移 / Source / Sink / 完整调用链（逐跳标注）/ 前置条件 / 影响 / 置信度 / 证据片段`

**置信度只写两态（对外）：`CONFIRMED` / `HYPOTHESIS`。** 内部三档（`confirmed`/`validated`/`candidate`）收敛规则见 `references/methodology.md` §4。**升级前必须过 `references/vuln-conditions.md` 的「通用四问」**（代码存在？可达？可控？防护？）——四问全绿才是最基础的门槛，再按漏洞类型过专属条件；任一不过就只能是 `HYPOTHESIS`，并**必须写明「缺哪一步才能升级」**。

标题格式：`F-001 · httpd Referer 头栈溢出`。**标题里不写评级**（`(Critical)` 之类），评级是表格里的字段。

---

### Phase 4 · 动态验证（把 validated 升成 confirmed）

静态链路完整 ≠ 可利用。固件场景还必须过三关：**能不能跑到这段代码**、**环境依赖（NVRAM/ioctl/硬件）能不能满足**、**有没有运行时防护**。

黑板上对应 `pending_dynamic_validation → validated → confirmed`：`validated` 是静态/仿真链路闭合，`confirmed` 是动态复现后的最终态；两步都要过 `board_transitions.py check` 的类型化证据校验（证据绑定同一 run/固件、漏洞类型对应的证据类型与判据、触发上下文）。状态与事件日志是审计留痕，不替代 `coverage_gate.py` 的门禁判定。

#### 前置：执行边界（在选路之前）

**默认只做静态分析；任何"运行固件里的东西"都必须先过这张表。** 固件是攻击者可控输入：CGI、init 脚本、ELF 都可能带恶意载荷，解析器本身也可能是攻击面。

| 阶段 | 是否执行固件内容 | 默认策略 |
|---|---|---|
| Phase 1 解包（moria / unblob / unsquashfs） | 只解析格式，不执行固件代码 | 可在宿主机；但**解析器漏洞**仍是攻击面，可疑镜像建议进沙箱 |
| Phase 2/3 直接执行 rootfs 里的脚本、CGI、init | **是** | **禁止**；需要动态行为就进沙箱 |
| Phase 4 整机模拟（qemu-system，D1） | **是**（内核 + init 启动） | 必须隔离 |
| Phase 4 单二进制模拟（Qiling / qemu-user，D5–D8） | **是** | 必须隔离 |
| Phase 4 模糊测试（AFL++，D10–D11） | **是** | 必须隔离 |
| 辅助工具（binwalk / mithril / strings） | 解析，不执行 | 可在宿主机；不要给外网、不要挂载真实设备 |

统一入口是 `scripts/sandbox_run.py`（纯标准库，Linux 用 docker/podman；Windows 需 Docker Desktop/WSL2）；它前面的准入层是 `scripts/resource_manager.py`（策略、跨进程槽位、墙钟预算）。两者都**只做执行边界，不做漏洞判定**。

```bash
# 只探测能力，不碰固件内容；退出码 0=可用 3=不可用
uv run scripts/sandbox_run.py --check

# 一次性隔离执行：无网络、只读固件、非 root、限内存/CPU/PID/时长
uv run scripts/sandbox_run.py \
    --firmware fw-audit/$TARGET/01-extract \
    --out      fw-audit/$TARGET/45-sandbox \
    --json     fw-audit/$TARGET/45-sandbox/run.json \
    --cmd      "cd /firmware && timeout 30 ./usr/sbin/httpd -h"
```

**五条硬规则：**

1. **fail-closed**：隔离运行时不可用时，脚本以 **退出码 3** 拒绝执行，并在 JSON 里写 `mode="fail-closed"`、`host_fallback=false`。**没有自动回退宿主机这条路径**——"探测失败"与"沙箱可用"在报告里必须长得不一样。
2. **宿主机执行只能显式授权**：`--mode host --i-understand-host-risk`，输出标记 `mode="host-opt-in"`、`policy.host_execution="explicit-opt-in"`。只用于完全可信的自建 rootfs。
3. **隔离参数固定**：`--network none`、`--read-only`、`--cap-drop=ALL`、`no-new-privileges`、`--user 65534:65534`、`--memory 512m --cpus 1 --pids-limit 128`、`/tmp` noexec、固件 `:ro`、输出目录与固件目录**不得重叠**。超时由 Python 侧 kill 并清理容器。容器内 uid 65534 与宿主机目录不做 UID 映射，sandbox 模式会为 `--out` 补 other rwx + sticky（0755 → 1757）后再挂载；host 模式不改用户原目录权限。
4. **留痕**：JSON 记录容器命令行、运行时版本、固件目录指纹（`sha256`）、退出码、stdout/stderr 头部、超时标志。动态结论必须能指回这份记录；**在宿主机直接跑固件二进制得到的结论不予采信**。
5. **先准入再启动**：`sandbox-run/1.1` 的 `admission` 必须记录策略哈希、申请资源、槽位等待与预算余量；`--check` 不占槽。准入被拒（退出 5）时不得留下部分产物，也不得改用宿主机重跑。

#### 资源准入

资源准入在启动前完成，超限**排队而不是先启动**；排队与执行都计入同一份墙钟预算：

```bash
# 策略可收紧：并发、排队上限、总预算、单命令超时、内存/CPU/PID、镜像白名单
uv run scripts/resource_manager.py validate --policy sandbox-policy.json

uv run scripts/sandbox_run.py \
    --firmware fw-audit/$TARGET/01-extract \
    --out      fw-audit/$TARGET/45-sandbox \
    --policy   sandbox-policy.json \
    --slots 1 --queue-timeout 60 --budget 300 \
    --cmd      "cd /firmware && timeout 30 ./usr/sbin/httpd -h"
```

`--slots` / `--queue-timeout` / `--budget` 只能收紧策略，不能放宽；准入拒绝退出码为 **5**，JSON 里 `command=[]`、`exit_code=null`，能从记录里区分「没启动」与「跑了但失败」。

**真实环境复验（2026-10-28）**：Ubuntu 24.04.5 LTS + Docker 29.9.0 + `debian:bookworm-slim`。容器内确认 `uid=65534`、仅 `lo`、`CapEff=0`、`NoNewPrivs=1`、内存 512 MiB、固件与根文件系统只读；`/out` 在补 other rwx + sticky 后可写。隐藏 docker 后 auto 退出 3 且不创建输出目录；`sleep 30` + `--timeout 2` 退出 124 且容器与临时目录清理；持槽时 `--queue-timeout 1` 退出 5、`--queue-timeout 15` 排队后成功；`--budget 2` 排队中耗尽预算退出 5。

#### 既有 EMBA 产物的离线导入（M3）

如果现场已经跑过 EMBA，**不要为了拿结论再启动一次 EMBA 或仿真**。`scripts/adapter_emba.py` 只读解析已有日志，输出 `emba-import/1.0`，并把三类观察分型落盘：

| 观察 | 来源 | `Fact.type` | 证据类型 | 不能证明什么 |
|---|---|---|---|---|
| 静态发现服务/组件 | L15 / S09 | `service` | `static` | 不能证明进程启动过，更不能证明端口可达 |
| 仿真进程实际有输出 | S115 | `runtime-process` | `emulation` | 不能证明该端口对外响应 |
| 系统仿真端口有响应 | L10 | `port-response` | `dynamic` | 不能反推具体漏洞或利用链 |

三类事实**不可互相升级**；Fact 落盘后不可改写，候选状态仍只能由 `board_transitions.py` 的类型化证据校验改变。F50 必需，其余日志可选；缺可选日志记 `MISSING_ARTIFACT` 且 `status=partial`，坏行报 `PARSE_ERROR`；`--require p99,s09,s115` 可把指定产物提升为本次审计必需，缺失即 `failed` + `MISSING_REQUIRED_ARTIFACT`（退出 1）。缺 F50、版本不符、固件哈希不符均为结构化失败。P99 的 PE32 落成 `file` 而不是 `elf`；L10 无开放端口时只记 limitation，不生成 `port-response`；F50 的 `user_emulation_state` 按成功仿真的**计数**解释。同一份日志重复解析字节一致。

```bash
# 只解析，不启动 EMBA/Qiling/QEMU；--strict 下 partial 退出 3
uv run scripts/adapter_emba.py parse --logs fw-audit/$TARGET/emba-logs \
    --run-id RUN-001 --firmware-sha256 <64-hex> \
    --firmware fw-audit/$TARGET/firmware.bin \
    --require p99,s09,s115 \
    --out fw-audit/$TARGET/05-emba-import.json --strict

# 导入黑板；先核对 run/固件绑定，failed 结果拒绝导入
uv run scripts/board_store.py import --workspace fw-audit/$TARGET/board \
    --emba fw-audit/$TARGET/05-emba-import.json
```

`assets/emba-sample/` 是按 EMBA HEAD `65b7870fb` 真实写入点对齐的**合成夹具**，只验证解析契约与格式细节；真实产物应替换夹具，并用 `--firmware` 核对固件哈希。字段与失败码见 `references/data-contracts.md` §17。

**整机仿真主路径不依赖 EMBA。** 没有现成日志时，不要为了导入去跑 EMBA；按 [references/emulation-methodology.md](references/emulation-methodology.md) 的 P0–P5，用 `qemu-system-*` + 最小 ext2 镜像 + user-mode 网络起整机，单次 60–120 秒、最多 3–4 轮。EMBA 的 2000 秒/2 GB、firmadyne 参数、TAP/网桥都不是默认必需；只有需要 L2/多网卡时才用 TAP，且放在独立 netns。

### 4.0 选路判据：要证明什么 → 需要哪组原子能力

**先问一个更高层的问题：你要把哪一条 HYPOTHESIS 升成 CONFIRMED？** 判据不是「哪个工具更强」，而是**结论类型决定能力组合**。完整决策树（含每个失败分支的处置）见 `references/atomic-capabilities.md` §3.2：

```text
Q1 要验证的是哪一类结论？
│
├─ (A) 整机 / 服务可达性（路由可达？认证状态？）
│   Q2 内核能否提取（E6）且 rootfs 完整（rootfs_ok）？
│    ├─ 能 → D1：qemu-system-<arch> + E7 的 bootargs 直接启动（完整判据见 references/emulation-methodology.md）
│    │    └ 启动失败 → D2 读串口/dmesg，按原因分支（不是换个仿真器重跑）：
│    │        ├─ no init found / VFS mount fail → D3 修 root= 或换 init
│    │        ├─ 找不到 root device（mtdblock?） → D3 改 mtdparts / 建节点
│    │        ├─ CPU/SoC 不匹配、无机器描述     → -M 或补 DTB（回 E7）
│    │        ├─ 卡在等硬件（watchdog/NVRAM）   → D3 改 init 或 stub 掉该步骤
│    │        └─ 内核与自带驱动不兼容           → 换厂商同版内核；仍不行 → 转 (B)
│    │    └ 启动成功 → D4 探测真实服务/路由，回 Phase 3 补证据
│    └─ 不能（内核加密/缺失/rootfs 不全）→ 直接转 (B)
│
├─ (B) sink 参数真值（命令注入 / 路径穿越 / 逻辑缺陷 / 认证绕过）
│    ├─ 能加载并跑到 sink → D5 Qiling + D6 打桩 + D7 hook sink 看实参真值
│    ├─ Qiling 因私有 syscall/加壳失败 → D8 strace/qemu-user + N2/N3 手工构造请求
│    └─ 完全无法执行 → 回退静态闭环（Phase 3），结论保持 HYPOTHESIS，不得声称已验证
│
├─ (C) 内存破坏是否真实存在（溢出 / UAF / 格式化）
│   Q4 目标二进制能否在宿主原生跑？
│    ├─ 能（同 arch / 可 native build）      → D10 afl-fuzz -O（FRIDA）
│    ├─ 跨 arch 且纯解析函数（无 syscall）    → D10 -U（Unicorn，最快）
│    ├─ 跨 arch 且依赖 libc/文件/socket       → D10 -Q（QEMU）
│    ├─ 是网络服务                            → 先 D5 写 harness（socket→文件）再喂 D10
│    └─ 有 magic / 校验和 / 长度比对          → D10 加 CmpLog（-c）或 laf-intel
│       然后 D11 逐个 triage 崩溃样本，判 PC 是否可控
│
└─ (D) 组件 CVE 是否可达 → 静态闭环（Phase 3 的「代码在 / 可达 / 未修复」三问），
    不需要仿真；只有当三问齐备、要复现时才回到 (A) 或 (B)。详见 §4.5。
```

**硬规则：**

1. **反馈优先于重试。** 起不来先去读输出（dmesg / 串口 / strace），定位到具体原因再针对性修补；**换实现是最后手段**。这正是本 skill 与整链仿真工具的根本区别——它们失败时只能换下一个工具，我们能改。
2. **不要为 fuzzing 而 fuzzing。** 只有 finding 类型是**内存破坏**（溢出 / UAF / 格式化），且静态链路已证可达时，才值得开 AFL++。**命令注入 / 认证绕过 / 路径穿越 / 逻辑缺陷用 D7 hook 直接看参数即可**——它们不是「跑崩了才算」，而是「参数到没到 sink」。对这类问题开 fuzzer 是纯浪费预算，且大概率一无所获。
3. **每条 HYPOTHESIS 都要落明确结论**：升成 CONFIRMED，或写清「为何在当前条件下不可验证」并保持 HYPOTHESIS。禁止用「未验证」当作无限期搁置的借口（铁律 4）。

**三种插桩模式速览**（同一套命令，模式决定插桩方式）：

| 模式 | 适用 | 相对速度 | 局限 |
|---|---|---|---|
| `-Q` QEMU | 跨架构黑盒，无需源码/插桩 | 中（~1–5k exec/s） | 需 AFL++ 的 qemu 支持该 arch |
| `-U` Unicorn | 纯函数，harness 把输入写进内存后调用 | 最快 | 不能有 syscall / 文件依赖 |
| `-O` FRIDA | 目标能在宿主原生跑或已 native build | 快 | 需 ptrace / root |

#### 4.1 整机模拟（D1）—— 手工 qemu-system 起步，编排工具只作对照

**先用最原始的通道起步**：错误信息最直接，启动失败时才知道该修什么（这就是「反馈优先于重试」）。

```bash
# D1：手工起（按 B1 识别的架构选 qemu-system-*；bootargs 来自 E7）
qemu-system-arm -M versatilepb -kernel vmlinux -dtb kernel.dtb \
  -append "root=/dev/mtdblock2 console=ttyAMA0,115200" \
  -drive file=rootfs.img,format=raw -nographic
# 起不来就用 D2：把串口输出/panic 原文读出来，按 §4.0 的失败分支定位修补点
```

```bash
# 想借编排工具的自动修补手法（NVRAM/网络/rootfs 修补）时，把它们当「对照组」而不是托管方
fat new ./firmware.bin && fat extract .fat-projects/<proj> && fat analyze .fat-projects/<proj>
fat startup-map --rootfs ./rootfs                           # 启动流程与真正会跑的服务（对照 F3）
fat trust-map --rootfs ./rootfs                             # 信任边界与可信二进制地图
fat r2-triage --file ./usr/sbin/httpd --json                # 二进制分诊（对照 B3/B5）
fat taint --file ./www/cgi-bin/diag.cgi --summary           # 污点追踪（对照 B6）
fat emulate --project .fat-projects/<proj> --instrument hooks.yaml   # 带 hook 跑
```

**用法红线**：`fat` 的这些子命令都是**对照与查漏**——它的结果与我们的 B3/B5/B6 输出比对，**差异即线索**；不要因为「它跑通了」就认为可达性已证。`fat emulate` 起来的服务**可能监听在可达网络上**，务必放在隔离网络 / 容器里，不要桥接到办公网。

#### 4.2 单二进制模拟（D5–D7）—— Qiling + 依赖打桩

整机模拟起不来时（依赖特定 NVRAM 布局、私有 ioctl、看门狗），用 Qiling 只跑目标二进制并给缺失依赖打桩：

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["./usr/sbin/httpd"], "./rootfs", verbose=QL_VERBOSE.DEFAULT)

def on_sink(ql):                     # 命中 sink 时记录参数真值
    print("cmd arg:", ql.mem.string(ql.arch.regs.read("r1")))

ql.hook_address(on_sink, 0x2a30)     # 地址取自 Layer 3 的静态定位
ql.run()
```

Qiling 的价值：**跨架构 + 跨平台 + 可 hook + 可热补丁**，能在 x86 宿主上跑 MIPS/ARM 的 `httpd`，并在 `system()` 入口看参数真值。详细打桩写法与踩坑见 `references/emulation-fuzzing.md`。

#### 4.3 模糊测试（D10–D11）—— AFL++（找内存破坏类缺陷）

封闭二进制无源码，用 AFL++ 的二进制模式：

```bash
# QEMU 模式（覆盖广，速度中等）
afl-fuzz -Q -i seeds/ -o out/ -- ./usr/sbin/httpd @@
# Unicorn 模式（速度快，适合纯计算型解析函数）
afl-fuzz -U -i seeds/ -o out/ -- ./parser @@
# FRIDA 模式（目标已能在宿主跑时）
afl-fuzz -O -i seeds/ -o out/ -- ./target @@

# 网络服务：用 Qiling 写 harness，把 socket 输入重定向到文件
afl-fuzz -Q -i seeds/ -o out/ -- python3 harness.py @@
```

语料与字典：从固件里提取协议字符串生成字典（`strings rootfs/usr/sbin/httpd | rg '^[A-Za-z_/]{4,}$' > dict.txt`），种子用真实请求。

崩溃判定：`out/default/crashes/`，逐个用 `qltool`/`gdb-multiarch` 复现，确认是否可控（PC 是否被污染）。**不要把 DoS 当 RCE 报。**

#### 4.4 硬件接口侧（受限条件下）

必须从物理接口取固件时（加密芯片、无升级包），走 UART/JTAG/SPI/SWD 路线，流程见 `references/resource-index.md` 的 Hardware Attacks 章节。此阶段产出的固件回到 Phase 1 重新入流水线。

#### 4.5 CVE 线索验证（⑥ → ④ 的唯一入口）

Phase 4 不只服务自研 finding，也是 **⑥ 组件风险（未验证）** 的唯一升级通道。对 Phase 1 登记进 ⑥ 的每条 `cve-hit` 逐条判定三问：

- **代码在**：固件内定位到受影响函数 / 符号（`mithril --cve` 只给版本，这一步要靠字符串、符号、反编译特征落实）；
- **可达**：从外部入口追出调用链，且前置条件在当前固件配置下成立；
- **未修复**：补丁特征不存在（对比厂商新版固件 / 检查关键分支是否缺失）。

三问齐备且静态闭环成立 → 按漏洞四问复核后**移入 ④**（`cve-reachable`；再经动态复现 → `cve-exploitable`）；任一项不成立 → 记 `cve-nonreachable`，移入 `30-findings-verified.md` 的 `NOT_FOUND` 台账。**每条都要落明确结论，不做「疑似但搁置」**——否则 ⑥ 会退化成无限期的垃圾抽屉。

产出：除 `40-coverage.md` 外，在 `30-findings-verified.md` 维护一张 **CVE 验证台账**（`CVE-ID → 三问逐项结论 → 迁移去向 F-0xx / NOT_FOUND`），供 Phase 5 生成报告时对账；迁移后同步更新统计（见 §5.3 第 6 区块）。

---

### Phase 5 · 门禁、沉淀与报告

#### 5.1 覆盖率门禁（硬性）

正式审计一律用 **strict 档位**——它强制启用全部高级检查，并且**任何必需检查未执行都判失败**：

```bash
uv run scripts/coverage_gate.py --profile strict \
    --plan fw-audit/<target>/03-audit-plan.md \
    --verified fw-audit/<target>/30-findings-verified.md \
    --candidates fw-audit/<target>/20-findings-candidates.jsonl \
    --review-list fw-audit/<target>/25-review-list.md \
    --tiering fw-audit/<target>/02-tiering.json \
    --entrypoints fw-audit/<target>/entrypoints.json \
    --taint-graph fw-audit/<target>/taint-graph.json \
    --layer1 fw-audit/<target>/10-layer1-sinks.json \
    --stages fw-audit/<target>/30-stages.json \
    --manifest fw-audit/<target>/00-manifest.json \
    --audit-task fw-audit/<target>/20-tasks.json \
    --require-structural \
    --report fw-audit/<target>/report.md \
    --out fw-audit/<target>/40-coverage.md
```

> 报告里只要出现「高阶 / high-order / 跨请求污点」这类声明，strict 档位就把 `--taint-graph` 变成**必需项**——声称高阶却没有图 = 不可复核 = 失败。没有高阶结论时可以不给，该项以 `SKIPPED` 列出且不判失败。

三个档位：`light`（只查覆盖率）/ `standard`（默认，未执行的高级检查以 `SKIPPED` 列出但不判失败）/ `strict`（需齐全输入 + 未执行即失败）。

**每项检查输出 `PASS` / `FAIL` / `WARN` / `SKIPPED` 四态。** `SKIPPED` 的含义是「本次没有执行」，不是「通过」；`WARN` 表示「降级但可继续」（例如结构引擎不可用而退回正则），不参与 `result` 判定但必须出现在报告里——旧版把未启用的检查从判据表里直接删掉，于是 `exit 0` 被误读成「G5 也通过了」。同时写 `40-coverage.gate-config.json`：档位、各项输入 SHA-256、每项检查状态、门禁版本，换机也能复算同一次判定。

`--report` 触发 **CVE 纪律检查**（铁律 7 的机械化落实）：扫描报告里是否把版本命中的组件 CVE 写成了漏洞断言（V1）、是否混进了「漏洞统计」表（V2）、是否被打了 P0-P3/CVSS（V3）、**同一 `CVE-ID` 是否同时出现在 ④ 与 ⑥（V4：应是「移动」而非「复制」）**、以及有没有单列「组件风险（未验证）」区块（V0）。命中即为门禁失败，退出码 1。

`--review-list` 触发 **审阅清单三方对齐**（Phase 2.5 的机械化落实）：diff「计划 vs 声明 vs 实际结论」，报 G1/G2/G3 三类缺口。

`--entrypoints` 触发 **G4 入口级覆盖**，`--bypass-check` 触发 **G5 绕过矩阵完备**，`--cross-request` 触发 **G6 跨请求污点溯源**，`--taint-graph` 触发 **G7 跨请求污点图**（写面/读面必须分属不同 action + 键一致 + 两端有地址与证据），`--type-base` 触发 **类型 → DKTSS Base 命中**校验；`--auto-recover` 把 G1/G3 转为自动修复计划。分述见下。

门禁判据（任一不满足则**不得出报告**，先补审）：
- T1 文件覆盖率 **100%**（每个文件必须有审计结论或明确的 `NOT_FOUND`）
- T2 文件覆盖率 ≥ 95%，未审文件必须列出理由
- 每条 `candidate` 必须有**结构化 `status`**，取值来自固定枚举：`hypothesis` / `confirmed` / `not_reproduced` / `not_applicable` / `pending_static_analysis` / `pending_dynamic_validation` / `blocked_by_environment`（另兼容旧写法 `validated` / `not_found`）。**「结论正文里出现过这个 ID」不算处置**；重复 ID、未知状态、`confirmed` 但缺 `evidence` 都判失败；候选清单为空需显式 `--allow-empty-candidates`，文件缺失直接判失败
- 所有 `promotions` 都要有对应的升级后分析
- 审阅清单一致：无 G1（声明未勾）/ G2（计划未声明）/ G3（勾选无结论）
- 报告完整性：9 个必填字段齐全（见 5.3）；**缺整个「漏洞详情」区块判失败**（不能因为「0 条待检查」而空集通过）
- 入口级覆盖（G4）：适用文件须有完整入口枚举 + 逐入口结论
- 绕过假设（G5）：凡「有防护 / 不可利用」断言必须附 B1–B12 矩阵
- 跨请求溯源（G6）：持久化存储来源的 finding 必须声明写入面
- 跨请求污点图（G7，给出 `--taint-graph` 时）：**写它的请求 ≠ 触发读的请求**、键两端字面一致、两端有 addr+evidence、sink 类型已知、跨进程读给出 `via_control`；报告声称高阶时图中必须有高阶链
- 扫描完整性（`--layer1`）：`sink_scan` 的 `scan_integrity.verdict` 为 `partial`/`failed` 即阻断；`scoped` 必须由 `--scan-waiver` 逐条豁免（`file` + `reason` + 豁免理由/复核人），未豁免缺口记 `LAYER1_*`
- 结构引擎完整性：`engine_status.verdict=failed` 无条件阻断；`partial` 默认 WARN，加 `--require-structural` 即失败
- 阶段状态（`--stages`）：`audit-stages/1.0` 的必需阶段必须为 `success`，否则 `STAGE_*`；声明与实测不一致记 `STAGE_INCONSISTENT`
- 清单与任务契约（`--manifest` / `--audit-task`）：`firmware-manifest/1.0` 与 `audit-task/1.0` 字段/枚举须通过 `contracts.py` 校验，`manifest_id` 必须与清单一致；镜像哈希不符即 `MANIFEST_HASH_MISMATCH`

脚本退出码非 0 表示未达标，缺口写入 `40-coverage.md` 的「待补审清单」，回去补。

##### G4 · 入口级覆盖（对抗「文件级 100%、函数级 0.2%」）

**为什么单列这条**：文件级覆盖会说「`usr/sbin/httpd` 有结论 → PASS」，哪怕它 2923 个函数只读了 5 个、167 个 CGI handler 一个没读。风险的真实单位是**入口**，不是文件。

适用对象：**T1 且 `text_kb > 200` 的服务型可执行**（`bin|sbin|usr/bin|usr/sbin` 下的 ELF，排除 `.so` 库）。用 `scripts/entrypoints_init.py` 生成骨架：

```bash
uv run scripts/entrypoints_init.py --tiering fw-audit/<target>/02-tiering.json \
    --out fw-audit/<target>/entrypoints.json --merge fw-audit/<target>/entrypoints.json
```

每个适用文件须有一条记录（schema `entrypoints/v1`）：

```json
{"file": "usr/sbin/httpd",
 "handler_table_count": 167,                  // 权威派发表条目数（必填）
 "enumerated_from": "IDA 0x186e28..0x187370 六段连续表",
 "handlers": [{"name": "ramain.cgi", "addr": "0x4ad44", "conclusion": "F-012"}]}
```

判据：①每个适用文件有记录；②`len(handlers) ≥ handler_table_count`（枚举完整）；③**每个入口有非空 `conclusion`**（已处置：finding id / `NOT_FOUND` / `待动态验证`）；④全局入口审计率 ≥ `--entrypoint-audit-min`（默认 100%）。
豁免只有两条，且都**留痕**：文件级 `waiver{reason}`，或 `entrypoints:"none"` + `reason`（无外部可达入口的 CLI 工具——它们是 sink 不是 source）。
显式给了 `--entrypoints` 却找不到文件 → **判失败**，绝不静默跳过。

##### G5 · 绕过矩阵完备（对抗「有防护」当结论）

凡是结论里写了「已鉴权 / 已过滤 / 已验签 / 已限长 / 有效校验 / 不可利用」，就必须在同一章节给出 **B1–B12 绕过矩阵**（检测 `bypass_matrix` 关键词，或 ≥10 个 B 条目号）。「修复建议」行是建议不是断言，不触发。
> 「有防护」≠「防护有效」。详见 Phase 3 的「绕过假设穷举」与 `references/methodology.md` §3.1。

##### G6 · 跨请求污点溯源（对抗「只审单请求」）

**为什么单列这条**：固件里最高频、也最难发现的一类漏洞是**跨请求**的——污点在请求 1 写入持久化存储（nvram / 文件 / IPC），在请求 2 才被读出并触发 sink。只审单请求的 source→sink 会认为「httpd 里 `wan_ifname` 没有写入点 → 不可控」，从而漏掉 RAXE500 `F-012`/`F-013` 那种整条链。

判据：凡 finding 的 `Source:` 指向**运行时写入的持久化存储**（nvram / uci 键，或 `/tmp`·`/var`·`/dev/shm` 等可写路径），就必须在**同一 finding 内**声明**写入面**（谁 / 哪个入口能写入该存储）。缺写入面 → 溯源未闭合，门禁 fail。

- 触发词：`nvram`·`acosNvramConfig`·`nvram_safe_get`·`uci`，以及 `/tmp/`·`/var/`·`/dev/shm`·`/mnt/`·`/data/`·`persist` 等路径。
- **静态配置不触发**（固件镜像内的 `.conf`/`.cfg`，如 RAXE500 `F-002` 的 `updater.conf`）——它们不是运行时写入的，避免误报。
- 写入面标记：`写入面`·`写端`·`write-face`·`可写`·`被写入`·`由…写入`·`导入`·`restore`·`nvram_set`·`acosNvramConfig_set`。
- 追踪方法（Track C）见 Phase 3 Layer 2 与 `references/methodology.md` §3.2。

##### 类型 → DKTSS Base 命中（防评分落空）

报告里每个 `类型:` 标签必须能命中 `references/reporting.md` 的 Base 表某一行，否则要么归一到已有类型、要么写「映射依据」、要么给 Base 表补一行。默认**告警**，`--type-base-strict` 转硬门禁。

##### G1/G2/G3 的自动修复（`--auto-recover`）

`--auto-recover [--max-rounds 2] [--recover-round N]`：G1/G3 转自动（重派 / 重总结，**不改变审计范围、不编造结论**），G2 **永不自动**（只能补充分片重审或书面 waiver）。超轮次后 G1/G3 亦回硬门禁。计划同时落盘为 `40-coverage.auto-recover.json` 供编排层消费。详见 `references/methodology.md` §5.1.1。


脚本退出码非 0 表示未达标，缺口写入 `40-coverage.md` 的「待补审清单」，回去补。

#### 5.2 规则沉淀

把已确认的漏洞模式固化成可复用规则，回灌 Layer 1 与 CI：

```
50-rules/
├── yara/                  # 二进制/固件特征（后门字符串、私有魔数、被篡改的 UPX 头）
├── grep/                  # 源码/脚本模式（比初始规则库更精确，已用真实样本调过）
└── sink-rules.patch.json  # 追加到 assets/sink-rules.json 的增量规则
```

每条规则注明来源 finding ID 与命中条件，避免「规则越加越多、噪声越来越大」。

#### 5.3 报告（固定 7 区块，不得缺项）

模板见 `assets/report-template.md`：

1. **执行摘要**：目标、固件版本、攻击面概览、漏洞数量按优先级分布、最严重 3 条
2. **目标与范围**：镜像 SHA256、提取方式、审计范围、覆盖率数字、未覆盖项及理由
3. **攻击面地图**：监听服务与端口、Web/CGI 路径、协议栈、启动服务、硬件接口、云侧对接
4. **漏洞详情**：ID / 标题 / 类型 / CVSS 3.1 向量 / IoT 语境修正 / 置信度 / 完整复现步骤 / 证据 / 修复建议
5. **加固与配置缺陷**（非漏洞但影响面）：ELF 加固缺失、硬编码凭据、调试接口、弱随机、无验签 OTA、U-Boot env 泄露
6. **组件风险（未验证）**：`mithril --cve` 命中的组件 CVE **单独成节，不并入第 4 区块**。每条注明「版本区间命中，**可达性未验证**」；已验证可达的才能升入第 4 区块并标注 `cve-reachable`/`cve-exploitable`。**禁止**把本节的条数计入漏洞总数，禁止在摘要里把它们写成「发现 N 个漏洞」。
   **⑥ ↔ ④ 迁移（与 Phase 4 联动）**：Phase 4 把 ⑥ 的线索逐条验证，通过（代码在 + 可达 + 未修复）即**「移动」而非「复制」**——从 ⑥ 删除、在 ④ 新建 `F-0xx`，⑥ 内只留一行「→ F-0xx」指针；排除项移入 `30-findings-verified.md` 的 `NOT_FOUND` 台账。**迁移后必须同步更新执行摘要统计表与优先级分布**（④ `+1`、⑥ 未验证 `−1`）。同一 `CVE-ID` 不得两处并存（门禁 **V4** 拦截）。完整状态机与措辞见 `references/reporting.md` §1-⑥。
7. **附录**：工具版本、命令回放、规则文件、敏感信息位置索引（值已脱敏）

#### 5.4 IoT 语境评分

CVSS 3.1 基础分不足以反映固件漏洞的实战价值。每条漏洞额外打三个修正维度，合成**优先级 P0-P3**：

| 维度 | 取值 | 权重 |
|---|---|---|
| Exposure 暴露面 | WAN 可达 / LAN 可达 / 需邻接（BLE、Zigbee）/ 需物理接触 | ×1.0 / 0.8 / 0.6 / 0.4 |
| AutoTrigger 触发成本 | 无需交互且出厂默认开启 / 需认证后可触发 / 需用户操作 / 需特殊构造 | ×1.0 / 0.7 / 0.4 / 0.2 |
| Impact 影响纵深 | 持久化 + 绕过安全启动 / 设备完全接管 / 沙箱内代码执行 / 信息泄露 / DoS | ×1.0 / 0.9 / 0.6 / 0.4 / 0.2 |

`实战分值 = CVSS_base × Exposure × AutoTrigger × Impact`
映射：`≥8.0 → P0`、`6.0-7.9 → P1`、`4.0-5.9 → P2`、`<4.0 → P3`。

**只对已验证可达的漏洞评分。** `cve-hit` 状态（仅版本命中）**不参与打分、不进优先级分布**——它的不可控变量太多（代码可能被裁剪、可能已 backport、可能需要未开启的编译选项），强行给分就是制造假优先级。未验证的组件 CVE 统一进第 6 区块，按 `EPSS × KEV` 排序作为「值得优先验证的线索」呈现。

优先修 P0/P1；P3（纯 DoS、需物理访问的信息泄露）在报告里明确标注「低优先，不影响量产决策」，避免优先级通货膨胀。

**DKTSS 并行评分（推荐主排序）**：上面的 IoT 修正是**乘法**模型，适合快排；但固件漏洞的真实价值差异几乎全在「利用阻力」——同一段代码，WAN 可达 vs 需拆机接 UART，实战价值差一个数量级。用 **DKTSS**（`Score = min(10, Base − Friction + Weapon + Ver)`）把阻力显式扣出来：Base 按类型+实际影响查表、Friction 按「访问路径 / 权限门槛 / 交互复杂度」三维累加扣除、Weapon 看有无现成 EXP、Ver 看版本。**当 CVSS 高而 DKTSS 低时，以 DKTSS 排序为准**（通常因为「需物理接触」或「需管理员」被 CVSS 忽略了）。完整表见 `references/reporting.md` §3.1。

---

## 参考文件

按需加载，不要一次全读：

| 文件 | 何时读 |
|---|---|
| `references/atomic-capabilities.md` | **决策判据 + 原子能力**：Phase 1 提取选路（§3.1）、Phase 4 仿真选路（§3.2）、54 项原子能力清单与实现命令（§1–§9）、整链工具的合法定位（§10.2）、能力缺席时的替代路径（§11） |
| `references/methodology.md` | 需要 Tier 规则细节、EALB 计算、三轨模型（Track A/B/C）、跨请求污点（§3.2）、门禁判据的完整定义 |
| `references/high-order-taint.md` | **高一阶/高阶污点的完整方法**：AEH 三形态与阈值、IPF 三模型、BDG 两段污点与按键入 join、OD-ICP 常量恢复、控制消息双约束、ADG 三类控制依赖、欠约束符号执行参数与坑、`taint-graph.json` 与 G7 判据、无 IDA/angr 时的降级路径 |
| `assets/ipc-functions.json` | IPC 原语词表（写/读端、键参数位置、控制/持久化标记、集中性阈值）+ sink 分类 + IPF 库函数 + AEH 识别模式 + SE 默认参数 |
| `references/vuln-taxonomy.md` | 需要按攻击面/漏洞类型逐项核查（后门账号、命令注入、OTA、MQTT、U-Boot…） |
| `references/vuln-conditions.md` | **Layer 3 / Phase 4**：候选要不要升 `CONFIRMED`？按漏洞类型逐条排除成立条件（固件版判定表） |
| `references/sink-patterns.md` | 需要扩充或理解静态扫描规则，或手写 grep / YARA |
| `references/emulation-methodology.md` | **Phase 4 整机仿真主路径**：P0–P5、架构/QEMU 矩阵、镜像构建、启动阶梯、网络模型、证据与失败分类；不依赖 EMBA |
| `references/emulation-fuzzing.md` | Phase 4 需要模拟与模糊的具体做法、踩坑与替代方案 |
| `references/reporting.md` | Phase 5 需要报告字段、评分表、脱敏规范 |
| `references/resource-index.md` | 需要外部资料：awesome-connected-things-sec 精编索引（按阶段映射） |
| `references/data-contracts.md` | **跨阶段数据契约**：17 种 schema——FirmwareManifest / AuditTask / Candidate / Finding / Evidence（含 `evidence/1.1` 归一化） / GateResult / AuditStages / ScanWaiver / SandboxRun / BenchManifest / EmbaImport / Fact / Intent / Hint / EmulationResult / BoardState / BoardEvent 的字段、版本规则、strict 兼容边界、黑板事件与状态机、**沙箱策略/资源准入/执行路径清单**、EMBA 导入、迁移清单 |

## 脚本

| 脚本 | 用途 |
|---|---|
| `scripts/fw_triage.py` | Phase 0 / 2：固件度量、熵扫描、ELF 加固画像、SUID 面、Tier 分层、EALB 预算 |
| `scripts/sink_scan.py` | Phase 3 Layer 1：多语言危险模式扫描（数据驱动规则） |
| `scripts/coverage_gate.py` | Phase 5：覆盖率门禁校验 + **CVE 纪律检查**（`--report`）+ **审阅清单三方对齐**（`--review-list`）+ **G4 入口级覆盖**（`--entrypoints`）+ **G5 绕过矩阵**（`--bypass-check`）+ **G6 跨请求污点溯源**（`--cross-request`）+ **G7 跨请求污点图**（`--taint-graph`）+ **类型→Base 命中**（`--type-base`）+ **自动修复计划**（`--auto-recover`）+ **`--profile {light,standard,strict}` 档位与 `gate-config.json` 执行台账** |
| `scripts/taint_graph.py` | Phase 3/5：跨请求污点图（BDG/ADG 最小实现）——`recover` 从反编译产物恢复常量键（literal / local-const / fill-composed），`build` 构图并校验「写请求 ≠ 触发读的请求、键一致、两端有证据、跨进程读带 via_control」；产出 `taint-graph.json` 供 G7 消费 |
| `scripts/entrypoints_init.py` | Phase 3/5：从 `02-tiering.json` 生成入口枚举骨架 `entrypoints.json`（G4 的输入） |
| `scripts/contracts.py` | Phase 0–5：数据契约校验（17 种 schema：FirmwareManifest / AuditTask / Candidate / Finding / Evidence / GateResult / AuditStages / ScanWaiver / SandboxRun / BenchManifest / EmbaImport / Fact / Intent / Hint / EmulationResult / BoardState / BoardEvent）；`--list` 列受支持版本，`--json` 出机器可读结果 |
| `scripts/board_transitions.py` | M1 / Phase 3–5：候选状态机——`graph` 列合法转换，`check` 做类型化证据校验（run/固件绑定、证据类型、判据、触发上下文），`risk` 校验风险处置而非候选状态 |
| `scripts/board_events.py` | M1：append-only 事件日志——`verify` 校验结构与 `seq` 连续性，`replay` 从日志重建快照；重复 `dedupe_key` 跳过，非法 JSON 行报错 |
| `scripts/board_store.py` | M1：黑板存储与导入——`init` / `import` / `add` / `transition` / `intent` / `backtrack` / `replay` / `verify` / `show`；`import --emba` 导入 M3 适配结果；事件日志是真相源，快照可重建 |
| `scripts/adapter_emba.py` | M3：EMBA 产物离线解析——F50/P99/S09/L15/L10/S115 → `emba-import/1.0`；三类观察分型（`service` / `runtime-process` / `port-response`）、PE32/ELF 区分、`--require` 显式产物、结构化失败、重复解析字节稳定 |
| `scripts/ealb_calib.py` | Phase 2：用实测工时样本校准 EALB；样本不足时只报 `heuristic`，达到门槛才标 `calibrated` |
| `scripts/sandbox_run.py` | Phase 4 / M2：不可信固件的一次性隔离执行（`--network none`、只读根、cap-drop、非 root、内存/CPU/PID 限额）；无隔离运行时 **fail-closed**（退出 3），宿主机执行必须显式授权；`sandbox-run/1.1` 记录资源准入（退出 5） |
| `scripts/resource_manager.py` | M2：`sandbox-policy/1.0` 策略校验、跨进程文件锁槽位、墙钟预算；`validate` / `defaults`；超限排队而不是先启动 |
| `scripts/exec_paths.py` | M2：AST 盘点 `scripts/*.py` 的子进程调用并分类（`sandbox-boundary` / `host-static-analyzer` / `trusted-metadata` / `test-harness`）；未分类即退出 1 |
| `scripts/bench_eval.py` | Phase 5/回归：合成基准集上的 precision / recall / F1 / FPR 评估；`--baseline` 检测召回暴跌与 FPR 上升（退出码 3） |
| `scripts/selftest.py` | 安装自检：生成合成固件与 rootfs，端到端验证其余十五个脚本的判据，并把**文档示例命令与 CLI 参数表对拍**；覆盖黑板事件/快照/状态机、资源准入与 EMBA 适配（23 组 / 254 条断言，结尾自报总数） |

脚本都只用 Python 标准库，无第三方依赖，Windows / Linux / macOS 均可运行。用 `uv` 管理环境（`uv run` 自动建临时环境；无 `uv` 时直接 `python scripts/xxx.py` 亦可）。安装后建议先跑一次自检：

```bash
uv run scripts/selftest.py
```

## 常见失败模式与纠正

| 症状 | 纠正 |
|---|---|
| 提取后只看了 `www/` 就下结论 | 回 Phase 2，按 R2/R3 补 `init.d`、`*.so`、CGI 二进制 |
| 报告里出现「可能存在格式化字符串漏洞」 | 触犯铁律 1：要么给 `文件:偏移` 证据，要么降级为「疑点」并说明未能验证的原因 |
| 二进制里出现 `system()` 就直接报 RCE | 必须完成 Source→Sink 追链，确认参数外部可控；否则只是 P3 代码质量项 |
| SquashFS 解不出来就放弃 | 按 `atomic-capabilities.md` §3.1 的判据换到 E2 的其它实现（sasquatch 版 `unsquashfs` 或 `moria -e`），两者都支持 SquashFS 全变体 |
| 一上来就跑解包工具、跳过侦察 | 回 §3.1 第 0 步：先 `file` + 熵 + 头部，拿到特征再选路；否则必然在非常规固件上乱试 |
| 某个能力失败，不看输出就换下一个重跑 | **反馈优先于重试**：先读输出（dmesg / 报错 / panic 原文）定位原因，针对性修补；换实现是最后手段 |
| 为了「稳」把 FAT / EMBA / 全家桶装齐 | 按 §3 判据**按需**装原子能力；整链工具只在主路径跑完后作交叉验证（§10.2），装它的时间通常换不来结论 |
| 整机模拟起不来就跳过 Phase 4 | 改用 D5 单二进制 + D6 打桩；再不行走静态闭环并标注「未经动态确认」 |
| 模糊跑两小时没崩就认为没漏洞 | 检查覆盖率（`afl-showmap`）、语料质量、目标是否真进入解析逻辑 |
| 把 `mithril --cve` 结果直接当漏洞报 | 组件版本命中 ≠ 设备可利用（可能未编译该功能 / 已打补丁 / 不可达）。必须验证可达性与触发条件。跑 `coverage_gate.py --report` 会自动拦下这类写法 |
| 「组件版本受影响所以漏洞存在」 | 五道缺口逐一排除：代码是否存在、是否 backport、编译选项、运行时配置、输入路径可达。版本号本身也可能被厂商改过 |
| 把 IDA/Ghidra 伪代码当原文证据引用 | 伪代码是反编译器的**推断**，函数边界与变量类型都可能错。伪代码用于理解控制流，证据必须是反汇编/字节 |
| 「我审完了」但说不出每个文件的结论 | 触犯 Phase 2.5：审阅清单逐项打勾，`coverage_gate.py --review-list` 会 diff 出 G1/G2/G3 缺口 |
| 扫到 `system()`/`strcpy()` 就报 RCE/溢出 | 过 `references/vuln-conditions.md` 的「通用四问」+ 类型专属条件；`system("常量")` 不是注入，`strcpy(dst, "字面量")` 不是溢出 |
| 一堆漏洞都是 P0 | 用 DKTSS 按 Friction 排序：需拆机接 UART 的 root 命令注入 `Base 10 − 4 = 6`（Medium），不该和 WAN 可达并列 P0 |
| 报告缺 Source/Sink/调用链 | 每条 finding 必过 9 字段校验，`coverage_gate.py --report` 缺字段即 exit 1 |
| `HYPOTHESIS` 没写「缺哪一步」 | 必须写清「升级所需的关键一步」，否则读者无法行动；门禁会检出 |
| 标题写成 `F-001 · 命令注入 (Critical)` | 评级放「优先级」字段，标题不含评级括注（门禁检出） |
