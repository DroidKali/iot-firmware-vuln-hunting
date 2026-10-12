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

**核心思路**（迁移自大可实验室《AI 挖 Java 0day 不再靠运气》上篇的流水线设计 + 下篇的质量保障机制）：Skill 不教模型「什么是命令注入」，那是它已知的；Skill 给它装上**资深固件审计员的工作骨架**——定义流程、分配资源、设置护栏、标准化输出，并把中间状态持久化到文件系统，不信任模型的记忆。文章里的「6 阶段流水线 + EALOC 分层 + 三层审计架构 + 双轨模型」在固件场景下逐条对应为下面的 Phase 0-5、EALB、Layer 1-3 与 Track A/B；下篇的「覆盖矩阵、CONFIRMED/HYPOTHESIS、漏洞成立条件表、DKTSS、报告必填字段」对应为 Phase 2.5、`vuln-conditions.md`、`reporting.md` §3.1 与 `coverage_gate.py` 的机械化门禁。

## 何时使用

使用：拿到固件镜像 / rootfs / 一堆嵌入式二进制，要做安全评估、漏洞挖掘、后门排查、渗透前置分析、SRC 众测前的自查。

不使用：纯 Web 应用源码审计（走代码审计流程）；纯硬件侧信道 / 电压毛刺（本 skill 只覆盖需要在固件里找软件漏洞的场景，硬件攻击面见 `references/resource-index.md` 的 Hardware Attacks 章节）。

## 前置：环境与授权

- **授权声明**：只在获得书面授权（自有设备 / 客户授权 / SRC 范围）的目标上执行。开工前把授权范围写进 `fw-audit/<target>/00-scope.md`。
- **环境**：`unblob` / `binwalk` / `moria` / `mithril` / `FAT` / `Qiling` / `AFL++` / `radare2` 在 Linux（Docker / WSL / Kali / AttifyOS）下体验最好。Windows 宿主请优先用 Docker；本 skill 自带的三个 Python 脚本是**纯标准库**，任何平台都能跑。
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

降级要在报告里**显式注明**，不要静默替换。**边界**：这条只适用于本机——提取出的 rootfs 里跑的是**目标设备 busybox** 的 `grep`/`find`，不能换，也不能用 `--include` 等 GNU 扩展。详见 `references/toolchain.md` §0.1。

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
├── 20-findings-candidates.jsonl Layer 2 双轨候选
├── 30-findings-verified.md      Layer 3 验证后结论（含 NOT_FOUND 台账）
├── 40-coverage.md               覆盖率门禁报告
├── 50-rules/                    Phase 5 沉淀的 YARA / grep 规则
└── report.md                    最终报告
```

| Phase | 名称    | 输入            | 输出                                               | 主要工具                          |
| ----- | ----- | ------------- | ------------------------------------------------ | ----------------------------- |
| 0     | 度量与定界 | 固件镜像          | `00-metrics.json`、`00-scope.md`                  | `scripts/fw_triage.py`        |
| 1     | 提取与侦察 | 固件镜像          | `01-extract/`、`01-manifest.json`                 | unblob → binwalk → moria 降级链  |
| 2     | 分层与分配 | `01-extract/` | `02-tiering.json`、`03-audit-plan.md`             | `scripts/fw_triage.py --tier` |
| 2.5   | 覆盖矩阵与审阅清单 | `03-audit-plan.md` | `25-review-list.md`                            | 人工/模型声明 + 门禁 diff |
| 3     | 三层审计  | 分配清单          | `10-layer1-sinks.json`、`30-findings-verified.md` | `scripts/sink_scan.py` + 模型审计 |
| 4     | 动态验证  | 候选漏洞          | 每条候选的可利用性判定                                      | FAT / Qiling / AFL++          |
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

按**降级链**执行，前一个失败才用后一个，并把策略与警告记进 `01-manifest.json`。

```bash
# 1) 首选：unblob（78+ 格式，chunk 起止精确，未知块也 carve）
unblob --report 01-manifest.json -e fw-audit/<target>/01-extract firmware.bin
unblob --show-external-dependencies     # 先确认外部解包器就绪；缺 sasquatch 会丢 SquashFS

# 2) 次选：binwalk v3（熵分析 + 签名识别，Rust 版更快更准）
binwalk -Me firmware.bin

# 3) 兜底：moria（进程内解 SquashFS/ext/F2FS/JFFS2/UBIFS/EROFS…，无需 root，默认递归）
moria -e firmware.bin -C fw-audit/<target>/01-extract
moria -j firmware.bin > moria-findings.json    # JSON 给脚本和模型消费
moria --list firmware.bin                      # 只看容器成员，不落盘

# 4) 单文件系统补刀
unsquashfs -d rootfs fw-audit/<target>/01-extract/0x…/squashfs-root
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

工具不齐时的替代：`FAT`、`firmwalker`、`EMBA`、`firmware-mod-kit`，清单见 `references/toolchain.md`。

提取后必做三件事，缺一不可（本机命令用 `fd`/`rg`，见 `references/toolchain.md` §0.1）：

1. `fd -t f -x file {}` → 建立类型清单（替代 `find . -type f -exec file {} +`）
2. `fd -t f -x sh -c 'test -u "$1" -o -g "$1" && echo "$1"' _ {}` → SUID/SGID
3. 读启动链：`etc/init.d/*`、`etc/rc.d/*`、`inittab`、`rcS`、`rc.local`、`hotplug`、`/etc/config/*` —— **启动链就是攻击面地图**，它告诉你哪些服务真正在跑

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

**效果示例**（真实形态的 IPC 固件）：T1 3.2MB 代码 + T2 8.4MB + T3 22MB →
  
`EALB = 3200 + 4200 + 2200 = 9600` → 12 个 Agent。
  
若按原始字节平均分：`(3.2+8.4+22)MB / 800KB ≈ 43` 个 Agent。**省下 72% 预算，深度不降。**

```bash
uv run scripts/fw_triage.py --rootfs fw-audit/<target>/01-extract \
    --tier --budget 800 --out fw-audit/<target>/02-tiering.json
```

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

**Layer 1 的定位是辅助参考，不是唯一入口。** 模型必须逐文件阅读分给它的全部代码，Layer 1 只负责告诉它「这里已知有危险形态，优先验证」。只看工具标记的文件，会系统性漏掉逻辑漏洞——认证绕过、状态机缺陷、签名校验缺失这类「本该有却没有」的问题，工具看不见。

#### Layer 2 —— 双轨审计（模型主场）

每个 Agent 对分到的文件跑**两条并行轨道**，按 Tier 决定深度。

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

**按 Tier 的深度**：

| Tier | 深度      | 具体动作                                                                                                       |
| ---- | ------- | ---------------------------------------------------------------------------------------------------------- |
| T1   | 全量 8 项  | ①入口枚举 ②数据流 ③安全控制逐项核查 ④敏感操作（文件/网络/加密/序列化/`insmod`/`ioctl`）⑤自定义封装库是否包了危险操作 ⑥配置与初始化 ⑦业务逻辑（状态机/竞态/条件判断）⑧绕过假设穷举 |
| T2   | 3 项     | 数据流 + 敏感操作 + 安全控制                                                                                          |
| T3   | 3 项模式匹配 | 硬编码凭据 / 调试接口 / 危险字符串                                                                                       |

**动态提升**：T2 文件里发现封装了危险操作 → 就地按 T1 分析；T3 文件里发现业务逻辑 → 提升到 T2。每次提升写进 `02-tiering.json` 的 `promotions` 数组，便于复盘。

候选结果逐行写入 `20-findings-candidates.jsonl`：

```json
{"id":"F-001","file":"usr/sbin/httpd","offset":"0x2a14","tier":"T1","track":"sink",
 "sink":"strcpy@0x2a30","source_hypothesis":"HTTP Referer header","rule":"P0-C-002",
 "evidence":"strings: 'Referer: %s' @0x1c40; disasm: strcpy r0,r1 @0x2a30",
 "confidence":"candidate","needs":"需确认 len 上限"}
```

#### Layer 3 —— 语义级链路验证

Layer 2 的候选必须验证 **Source→Sink 可达性**。按「有没有 MCP」分两条路，**都要走**，MCP 只是把手工路自动化了。

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

配置（写进 `~/.workbuddy/mcp.json` 的 `mcpServers`，改完需在连接器管理页点「信任」才生效）：

```json
{"mcpServers": {"ida": {"command": "uvx",
  "args": ["--exclude-newer=1s", "ida-mcp", "stdio", "--agent=workbuddy"]}}}
```

**MCP 的硬前置与坑**：需 IDA 9.4+ 与 idalib 授权（商业授权，**没有就退回路径 B**）；`execute_python` 默认 `flush_database=True` 会立刻写 `.id0/.id1`，**对固件二进制是写操作**——先在副本上跑；一条命令超时（默认 360s）只是「请求中断」，阻塞型 `sleep()` 可能仍在跑；失败**不自动重试**（可能已改库）。

**路径 B：无 MCP 时的降级链（任何环境都必须能跑）**

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

#### 4.1 整机模拟 —— FAT（首选，编排完整）

```bash
fat ./firmware.bin                                          # 识别
fat new ./firmware.bin
fat extract .fat-projects/<proj>
fat analyze .fat-projects/<proj>
fat trust-map --rootfs ./rootfs                             # 信任边界与可信二进制地图
fat startup-map --rootfs ./rootfs                           # 启动流程与真正会跑的服务
fat search --rootfs ./rootfs --profile credentials -I --context 2
fat r2-triage --file ./usr/sbin/httpd --json                # 二进制分诊
fat taint --file ./www/cgi-bin/diag.cgi --summary           # 污点追踪（source→sink）
fat taint-cross --rootfs ./rootfs                           # 跨二进制污点
fat emulate --project .fat-projects/<proj>                  # 起模拟（QEMU 编排）
fat emulate --project .fat-projects/<proj> --instrument hooks.yaml   # 带 hook 跑
```

`fat emulate` 起来的服务**可能监听在可达网络上**，务必放在隔离网络 / 容器里，不要桥接到办公网。

#### 4.2 单二进制模拟 —— Qiling（依赖硬件时打桩）

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

#### 4.3 模糊测试 —— AFL++（找内存破坏类缺陷）

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

---

### Phase 5 · 门禁、沉淀与报告

#### 5.1 覆盖率门禁（硬性）

```bash
uv run scripts/coverage_gate.py \
    --plan fw-audit/<target>/03-audit-plan.md \
    --verified fw-audit/<target>/30-findings-verified.md \
    --review-list fw-audit/<target>/25-review-list.md \
    --tiering fw-audit/<target>/02-tiering.json \
    --report fw-audit/<target>/report.md \
    --out fw-audit/<target>/40-coverage.md
```

`--report` 触发 **CVE 纪律检查**（铁律 7 的机械化落实）：扫描报告里是否把版本命中的组件 CVE 写成了漏洞断言（V1）、是否混进了「漏洞统计」表（V2）、是否被打了 P0-P3/CVSS（V3）、以及有没有单列「组件风险（未验证）」区块（V0）。命中即为门禁失败，退出码 1。

`--review-list` 触发 **审阅清单三方对齐**（Phase 2.5 的机械化落实）：diff「计划 vs 声明 vs 实际结论」，报 G1/G2/G3 三类缺口。

门禁判据（任一不满足则**不得出报告**，先补审）：
- T1 文件覆盖率 **100%**（每个文件必须有审计结论或明确的 `NOT_FOUND`）
- T2 文件覆盖率 ≥ 95%，未审文件必须列出理由
- 每条 `candidate` 必须有明确处置：升 `validated` / 降 `NOT_FOUND` / 标记「证据不足，待动态验证」
- 所有 `promotions` 都要有对应的升级后分析
- 审阅清单一致：无 G1（声明未勾）/ G2（计划未声明）/ G3（勾选无结论）
- 报告完整性：9 个必填字段齐全（见 5.3）

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

#### 5.3 报告（固定 6 区块，不得缺项）

模板见 `assets/report-template.md`：

1. **执行摘要**：目标、固件版本、攻击面概览、漏洞数量按优先级分布、最严重 3 条
2. **目标与范围**：镜像 SHA256、提取方式、审计范围、覆盖率数字、未覆盖项及理由
3. **攻击面地图**：监听服务与端口、Web/CGI 路径、协议栈、启动服务、硬件接口、云侧对接
4. **漏洞详情**：ID / 标题 / 类型 / CVSS 3.1 向量 / IoT 语境修正 / 置信度 / 完整复现步骤 / 证据 / 修复建议
5. **加固与配置缺陷**（非漏洞但影响面）：ELF 加固缺失、硬编码凭据、调试接口、弱随机、无验签 OTA、U-Boot env 泄露
6. **组件风险（未验证）**：`mithril --cve` 命中的组件 CVE **单独成节，不并入第 4 区块**。每条注明「版本区间命中，**可达性未验证**」；已验证可达的才能升入第 4 区块并标注 `cve-reachable`/`cve-exploitable`。**禁止**把本节的条数计入漏洞总数，禁止在摘要里把它们写成「发现 N 个漏洞」。
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
| `references/toolchain.md` | 需要具体命令、安装方式、工具缺失时的替代方案 |
| `references/methodology.md` | 需要 Tier 规则细节、EALB 计算、双轨模型、门禁判据的完整定义 |
| `references/vuln-taxonomy.md` | 需要按攻击面/漏洞类型逐项核查（后门账号、命令注入、OTA、MQTT、U-Boot…） |
| `references/vuln-conditions.md` | **Layer 3 / Phase 4**：候选要不要升 `CONFIRMED`？按漏洞类型逐条排除成立条件（固件版判定表） |
| `references/sink-patterns.md` | 需要扩充或理解静态扫描规则，或手写 grep / YARA |
| `references/emulation-fuzzing.md` | Phase 4 需要模拟与模糊的具体做法、踩坑与替代方案 |
| `references/reporting.md` | Phase 5 需要报告字段、评分表、脱敏规范 |
| `references/resource-index.md` | 需要外部资料：awesome-connected-things-sec 精编索引（按阶段映射） |

## 脚本

| 脚本 | 用途 |
|---|---|
| `scripts/fw_triage.py` | Phase 0 / 2：固件度量、熵扫描、ELF 加固画像、SUID 面、Tier 分层、EALB 预算 |
| `scripts/sink_scan.py` | Phase 3 Layer 1：多语言危险模式扫描（数据驱动规则） |
| `scripts/coverage_gate.py` | Phase 5：覆盖率门禁校验 + **CVE 纪律检查**（`--report`）+ **审阅清单三方对齐**（`--review-list`），输出待补审与违规清单 |
| `scripts/selftest.py` | 安装自检：生成合成固件与 rootfs，端到端验证上面三个脚本的判据 |

四个脚本都只用 Python 标准库，无第三方依赖，Windows / Linux / macOS 均可运行。用 `uv` 管理环境（`uv run` 自动建临时环境；无 `uv` 时直接 `python scripts/xxx.py` 亦可）。安装后建议先跑一次自检：

```bash
uv run scripts/selftest.py
```

## 常见失败模式与纠正

| 症状 | 纠正 |
|---|---|
| 提取后只看了 `www/` 就下结论 | 回 Phase 2，按 R2/R3 补 `init.d`、`*.so`、CGI 二进制 |
| 报告里出现「可能存在格式化字符串漏洞」 | 触犯铁律 1：要么给 `文件:偏移` 证据，要么降级为「疑点」并说明未能验证的原因 |
| 二进制里出现 `system()` 就直接报 RCE | 必须完成 Source→Sink 追链，确认参数外部可控；否则只是 P3 代码质量项 |
| SquashFS 用 `binwalk -e` 没解出来就放弃 | 换 `unblob`（需 sasquatch）或 `moria -e`，两者都支持 SquashFS 全变体 |
| 整机模拟起不来就跳过 Phase 4 | 改用 Qiling 单二进制 + 打桩；再不行做静态链路并标注「未经动态确认」 |
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
