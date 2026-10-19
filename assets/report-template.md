# <设备型号> 固件安全评估报告

> 本模板为 Phase 5 的强制结构。**7 个区块不得缺项**；`<...>` 为占位符，`<!-- -->` 为填写指引，交付前删除指引。
>
> **每条漏洞（第 4 区块）必须包含 9 个必填字段**：类型 / 位置 / 优先级 / 置信度 / CVSS 3.1 / Source / Sink / 完整调用链 / 证据。`coverage_gate.py --report` 会逐条校验，缺任一字段即报告生成失败。

| 项目 | 内容 |
|---|---|
| 报告版本 | v1.0 |
| 评估日期 | <YYYY-MM-DD> |
| 目标设备 | <厂商 / 型号 / 硬件版本> |
| 固件版本 | <版本号 / 构建号> |
| 固件来源 | <官网下载 / 出厂提取 / UART dump / SPI dump> |
| 固件指纹 | `SHA256: <hash>` |
| 文件大小 | <bytes / MB> |
| 评估方 | <团队 / 人员> |
| 授权依据 | <合同 / SRC 范围 / 自有设备> |

---

## 1. 执行摘要

### 结论

<一句话：该固件的整体风险等级（严重 / 高 / 中 / 低），以及最需要优先修复的问题。>

### 攻击面概览

| 维度 | 数量 | 说明 |
|---|---|---|
| 对外监听服务 | <n> | <例：HTTP:80、HTTPS:443、Telnet:23、UDP:1900> |
| Web / CGI 入口 | <n> | <例：12 个 cgi-bin 路由，其中 5 个未认证> |
| 协议栈 | <n> | <例：UPnP、HNAP、mDNS、MQTT> |
| 硬件调试接口 | <n> | <例：UART（root shell）、未熔断 JTAG> |
| 云侧对接 | <n> | <例：AWS IoT MQTT、厂商 OTA 服务器> |

### 漏洞统计

> 本表**只统计已验证可达的漏洞**。`cve-hit`（仅版本命中的组件 CVE）**不进本表**，
> 单独列于第 6 区块，并在下方「组件风险」一行体现，不计入合计。

| 优先级 | CONFIRMED | HYPOTHESIS | 合计 |
|---|---|---|---|
| P0 | | | |
| P1 | | | |
| P2 | | | |
| P3 | | | |
| **合计** | | | |

> `HYPOTHESIS` 单独一列以便读者一眼看出「还有多少未定论」。若某条 `HYPOTHESIS` 的
> 缺项已补齐并升为 `CONFIRMED`，从本列移入左列。

- **组件风险（未验证，不计入合计）**：`cve-hit` <n> 条，详见第 6 区块

### 最严重的 3 条

1. **<F-00x 标题>**（P0，CONFIRMED）— <一句话影响>
2. **<F-00x 标题>**（P0，CONFIRMED）— <一句话影响>
3. **<F-00x 标题>**（P1，HYPOTHESIS：<缺哪一步>）— <一句话影响>

---

## 2. 目标与范围

### 提取与审计方式

| 步骤 | 工具 / 版本 | 结果 |
|---|---|---|
| 提取 | <unblob x.y / binwalk z / moria v> | <提取出 n 个文件系统，总 n GB> |
| 内容扫描 | <mithril v> | <secrets/SBOM/CVE/boot/keys 结果摘要> |
| 分层 | `fw_triage.py` | T1 <a> / T2 <b> / T3 <c> / SKIP <d>，EALB <e>，Agent 数 <f> |
| 静态扫描 | `sink_scan.py` | Layer 1 命中 <n> 条（P0:<x> P1:<y> P2:<z> P3:<w>） |
| 动态验证 | <FAT / Qiling / AFL++> | <成功模拟的服务，模糊时长与覆盖率> |

### 覆盖率（必须来自 `40-coverage.md`）

| 范围 | 文件数 | 已审计 | 覆盖率 | 门禁 |
|---|---|---|---|---|
| T1 | | | 100%（要求） | <PASS/FAIL> |
| T2 | | | <x>%（要求 ≥95%） | <PASS/FAIL> |
| T3 | | | <x>% | |
| SKIP（关键字扫描） | | | 100%（要求） | <PASS/FAIL> |

### 未覆盖项及理由

| 范围 | 原因 | 后续建议 |
|---|---|---|
| <例：0x800000 后的加密分区> | <未取得解密密钥> | <需硬件侧读出或向厂商索取> |
| <例：私有 ioctl 路径> | <需真实硬件外设> | <需真机验证> |

### 测试环境与限制

<例：审计在 Docker 隔离环境内完成；动态验证基于 FAT 的 QEMU 模拟（未使用真机）；模糊测试累计 6 小时，目标函数覆盖率 41%。>

---

## 3. 攻击面地图

### 网络服务

| 端口 | 协议 | 进程 | 默认开启 | 认证 | 备注 |
|---|---|---|---|---|---|
| 80/tcp | HTTP | `usr/sbin/httpd` | 是 | 部分路径无 | <...> |
| 23/tcp | Telnet | `usr/sbin/telnetd` | <是/否> | <无/有> | <...> |

### Web / CGI 路由与鉴权状态

| 路由 | 功能 | 鉴权 | 备注 |
|---|---|---|---|
| `/cgi-bin/ping` | 网络诊断 | **无** | 见 F-007 |
| `<...>` | | | |

### 启动链（真正运行的服务）

```
<粘贴 init.d / rcS / inittab 的关键行，标注哪些服务会被拉起>
```

### 协议栈

<UPnP / HNAP / MQTT / CoAP / TR-069 / 私有协议，以及各自是否需认证>

### 硬件接口

| 接口 | 是否开放 | 可获得 | 说明 |
|---|---|---|---|
| UART | <是> | <root shell> | <115200 8N1，启动可打断 U-Boot> |
| JTAG / SWD | <否> | — | <已熔断> |
| SPI Flash | — | <可读出> | <未加密> |

### 云侧对接

| 端点 | 用途 | 凭据方式 | 备注 |
|---|---|---|---|
| `<https://...>` | OTA | <证书 / 无校验> | <...> |

---

## 4. 漏洞详情

<!-- 每条漏洞使用下面的完整模板，不得删减字段。按优先级从高到低排列。 -->

### F-001 · <标题>

> 标题**不含评级**（不写 `(Critical)`）——评级是下面「优先级」字段。

<!-- 以下 9 个字段必填，缺任一 → 报告生成失败（coverage_gate.py --report 校验） -->
- **类型**：<command-injection (CWE-78) / stack-buffer-overflow (CWE-121) ...>
- **位置**：`<文件:0x偏移>` 或 `<文件:行号>`
- **优先级**：<P0>（DKTSS <X> / CVSS <Y.Y>）
- **置信度**：<CONFIRMED / HYPOTHESIS>（HYPOTHESIS 时必须紧跟「缺项」说明）
- **CVSS 3.1**：`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = <9.8>
- **Source**：<数据来源与完整路径>
- **Sink**：<危险操作与位置>
- **完整调用链**：
  1. `<函数> @0x...`
  2. `<函数> @0x...`（标注关键分支/校验缺失）
  3. `<sink> @0x...`
- **证据**：
  - `[E1]` disasm `<文件@0x...>`：`<指令 + 注释>`
  - `[E2]` `strings -tx`：`<偏移> <字符串>`
  - `[E3]` <动态验证输出 / 日志 / 截图路径>

<!-- 以下为推荐字段（CONFIRMED 强烈建议补全；HYPOTHESIS 必须写「缺项」） -->

- **IoT 修正**：Exposure ×<1.0>（<WAN 可达>）· AutoTrigger ×<1.0>（<出厂默认开启>）· Impact ×<0.9>（<设备完全接管>）→ 实战分值 <X.X>
- **DKTSS**：Base <10> − Friction <0>（访问 <0>/权限 <0>/交互 <0>）+ Weapon <1> + Ver <0> = <9>
- **成立条件判定**（按 `references/vuln-conditions.md` 填）：
  | 四问 | 结果 | 依据 |
  |---|---|---|
  | Q1 代码存在 | <是> | <反汇编定位 @0x...> |
  | Q2 路径可达 | <是> | <入口 = /cgi-bin/ping> |
  | Q3 输入可控 | <是> | <来源 = HTTP query，无过滤> |
  | Q4 防护阻断 | <无> | <NX 关闭 / 无 Canary> |
  - **缺项**（HYPOTHESIS 必填）：<缺哪一步才能升级，如「未确认真机上该服务默认开启」>
- **前置条件**：<无认证 / 需认证 / 需邻接 / 需物理>
- **复现步骤**：
  ```bash
  <可直接执行的命令序列>
  ```
- **影响**：<能做什么、危害半径、是否需要持久化>
- **修复建议**：
  1. 立即：<具体到函数/参数/配置项>
  2. 根本：<架构或实现层面的修改>
  3. 加固：<编译选项 / 运行权限 / 网络隔离>

<!-- 重复上述结构 -->

---

## 5. 加固与配置缺陷

> 本节记录不是单点漏洞、但会放大其他漏洞危害的问题。

### 二进制加固画像

| 二进制 | NX | PIE | Canary | RELRO | FORTIFY | `.text` |
|---|---|---|---|---|---|---|
| `usr/sbin/httpd` | <否> | <否> | <否> | <Partial> | <否> | <184KB> |
| 统计 | <n/m 缺失> | | | | | |

<说明：无 NX + 无 PIE 会让第 4 节的栈溢出直接升级为可用 RCE。>

### 硬编码凭据

| 类型 | 位置 | 指纹 | 备注 |
|---|---|---|---|
| <私钥> | `<路径>` | `SHA256:ab12cd34…` | <全网共用> |
| <云端 token> | `<路径>` | `<前 4 位>…（<长度> 字符）` | <...> |

<!-- 完整值见 50-secrets.local，不随报告分发 -->

### 其他加固缺陷

- **调试接口**：<例：telnetd 默认开启，口令 root/root>
- **弱随机**：<例：会话 token 用 srand(time(NULL))+rand() 生成>
- **升级通道**：<例：升级包仅校验 CRC，可篡改后重算>
- **信任链**：<例：U-Boot env 分区可写；AVB 未启用>（引用 `mithril --boot` 输出）

### 加固建议优先级

1. <改动最小、收益最大的项>
2. <...>

---

## 6. 组件风险（未验证）

> ⚠️ **本节不是漏洞清单。** 以下条目来自版本比对（`mithril --cve` / SBOM），
> 仅表示「组件版本落在 CVE 影响区间」，**未验证代码是否存在、是否可达、是否已修复**。
> **本节条数不计入第 4 区块的漏洞总数。** 措辞统一为「疑似…尚未验证可达性」。

| CVE | 组件@版本 | KEV | EPSS | 影响描述 | 待验证项 |
|---|---|---|---|---|---|
| <CVE-XXXX-YYYY> | <busybox 1.31> | <是/否> | <0.xx> | <...> | <代码是否存在 / 调用链是否存在 / 补丁是否已打> |

**优先验证顺序**（KEV 优先 → EPSS 降序）：

1. <CVE-...> — <为什么值得先查，如：KEV 在野利用 + 组件在 WAN 可达路径上>
2. <...>

**已验证并升入第 4 区块的条目**（**移动，不是复制**——同一 `CVE-ID` 不得同时留在上表与本表，门禁 **V4** 拦截；升级后须同步「漏洞统计」表与第 4 区块优先级分布）：

| CVE | 状态 | 升级依据 |
|---|---|---|
| <CVE-...> | `cve-reachable` | <已定位函数 @0x... + 调用链 F-00x> |
| <CVE-...> | `cve-exploitable` | <复现见 evidence/...> |

**已排除的条目**（避免后人重复劳动）：

| CVE | 排除理由 |
|---|---|
| <CVE-...> | <受影响 applet 未编译进固件> |
| <CVE-...> | <厂商已 backport，补丁特征存在于 @0x...> |

---

## 7. 附录

### 工具与版本

| 工具 | 版本 |
|---|---|
| unblob | |
| binwalk | |
| moria / mithril | |
| FAT / Qiling / AFL++ | |
| radare2 | |
| ida-mcp / IDA（如使用逆向 MCP） | |
| Python | |

### 关键命令回放

```bash
# Phase 0
uv run scripts/fw_triage.py <firmware.bin> --out 00-metrics.json
# Phase 1
unblob --report 01-manifest.json -e 01-extract <firmware.bin>
mithril -j 01-extract > mithril.json
# Phase 2
uv run scripts/fw_triage.py --rootfs 01-extract --tier --budget 800 --out 02-tiering.json --plan 03-audit-plan.md
# Phase 3
uv run scripts/sink_scan.py 01-extract --rules assets/sink-rules.json --json 10-layer1-sinks.json
# Phase 5（正式审计一律 strict 档位：全开高级检查，未执行即失败）
uv run scripts/coverage_gate.py --profile strict \
    --plan 03-audit-plan.md --verified 30-findings-verified.md \
    --candidates 20-findings-candidates.jsonl --tiering 02-tiering.json \
    --report report.md --out 40-coverage.md
```

### 规则文件

`50-rules/` — YARA 与 grep 规则索引，每条注明来源 finding ID。

### 敏感信息位置索引

| 路径 | 类型 | 指纹 |
|---|---|---|
| `<路径>` | <私钥 / 口令哈希 / token> | <指纹> |

### 术语与缩写

| 缩写 | 全称 |
|---|---|
| EALB | Effective Analysis Load Bytes |
| Tier | 分层级别（T1 外部输入入口 / T2 业务与库 / T3 静态数据） |
| Track A/B | Sink-driven / Control-driven 审计轨道 |
