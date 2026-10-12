# 方法论完整定义

本文件定义 Phase 0-5 的判据与算法细节，以及**方法论来源映射**。SKILL.md 给的是骨架，这里给的是可执行的规则。

## 0. 方法论来源映射

本 skill 把「AI 代码审计 Skill 体系」的设计思路迁移到固件场景。迁移关系如下——理解这张表有助于在遇到新情况时判断「该用哪条原则」：

| 原方法论（Java 代码审计） | 固件场景的等价物 | 为什么这样迁移 |
|---|---|---|
| Phase 0 代码库度量（LOC、Controller 数） | 固件度量：熵扫描、架构、二进制数、`.text` 总量、SUID 面 | 固件没有「文件行数」这个直觉指标，`.text` 才是真实工作量 |
| Tier 分层：Controller / Service / Entity | T1 外部输入入口 / T2 业务与库 / T3 静态数据 | 分层依据从「架构角色」换成「是否可达外部输入」 |
| EALOC = T1×1.0 + T2×0.5 + T3×0.1 | EALB = Σ tier_weight × text_KB | 单位从「行」换成「代码段 KB」，因为固件里二进制占主体 |
| Layer 1：ripgrep + Semgrep 全量预扫描 | `fw_triage.py` + `sink_scan.py` 多语言规则扫描 + mithril 内容扫描 | 固件没有源码语义分析，只能靠字符串/符号/配置模式 |
| Layer 2：双轨审计（Sink-driven / Control-driven） | 完全保留，且固件场景 Track B 权重更高 | 固件的认证绕过、无验签 OTA 占比高于 Java 的 SQL 注入类 |
| Layer 3：LSP 语义追踪 | **MCP 反编译（IDA `ida-mcp` / `pyghidra-mcp`）→ Ghidra 无头 → radare2 交叉引用 + 字符串锚点回溯** | 固件没有 LSP；MCP 让「字符串→引用点→调用者」三跳变成一条 xref 查询 |
| Phase 4：Semgrep 规则沉淀 | YARA / grep / sink-rules 增量沉淀 | 二进制场景 YARA 更合适 |
| 覆盖率门禁 100% | 保留，T1 必须 100%，并新增「审阅清单三方对齐」（计划 ↔ 声明 ↔ 结论） | 唯一能对抗「随机游走」与「声称 100% 实际 70-85%」的硬约束 |
| 反幻觉规则 | 完全保留，且新增「脱敏」「CVE 命中≠漏洞」「漏洞成立条件四问」三条 | 固件会挖出真实凭据；SBOM/CVE 比对极易被误报成「漏洞」；危险调用遍地都是 |
| CONFIRMED / HYPOTHESIS 两态 | 保留，作为对外唯一置信度状态 | 读者不该在四五个 confidence 词里迷路 |
| 漏洞成立条件判断表 | 迁移并固件化（`vuln-conditions.md`）：命令注入/内存破坏/认证绕过/OTA/MQTT 等 10 类 | 工具扫出的「危险调用」不是漏洞，需逐条排除成立条件 |
| DKTSS 评分 | 迁移并固件化：Friction 维度增加「物理接触 −4」 | 固件漏洞的真实价值差异几乎全在利用阻力（WAN vs 拆机） |
| 6 核心块报告 | 改为固件 7 区块 + IoT 语境评分 + DKTSS，且 9 字段必填校验 | 报告读者从开发团队变成产品/安全决策方；组件 CVE 必须单列 |

**关键不变式**：模型的记忆不可信 → 一切中间结论落盘；模型的判断不可信 → 一切结论要证据；模型的注意力不均衡 → 用 Tier 和门禁强制分配。

---

## 1. Tier 分层规则（完整版）

规则按顺序匹配，命中即停。实现见 `assets/tier-rules.json` 与 `scripts/fw_triage.py`。

### R0 · SKIP

路径匹配（不区分大小写）：

```
**/doc/**, **/docs/**, **/man/**, **/info/**, **/share/locale/**, **/locale/**,
**/zoneinfo/**, **/terminfo/**, **/licenses/**, **/LICENSE*,**/COPYING*,
**/fonts/**, **/usr/share/terminfo/**,
*.png *.jpg *.jpeg *.gif *.svg *.ico *.woff *.woff2 *.ttf *.eot
/var/lib/dpkg/**, /var/lib/opkg/**, /var/lib/apk/**, /usr/lib/opkg/**
```

处理方式：**不做语义审计**，但仍参与 Layer 1 的字符串级凭据扫描（P2/P3 规则），因为文档/JS 里可能藏 URL 与 token。

### R1 · 动态提升为 T1

输入：`10-layer1-sinks.json` 中该文件是否有 `priority` 为 `P0` 或 `P1` 的命中。
命中理由与提升记录写入 `02-tiering.json.promotions`：

```json
{"file":"usr/lib/libnvram.so","from":"T2","to":"T1",
 "reason":"Layer1 P0 hit: system() string @0x1f20","finding_ids":["L1-0042"]}
```

### R2 · T1（外部输入入口）

判据（任一命中）：

- **文件名/路径**：`cgi-bin/`、`*.cgi`、`www/` 下的可执行、`htdocs/` 下可执行
- **已知服务名**：`httpd` `lighttpd` `uhttpd` `boa` `goahead` `webs` `mini_httpd` `upnpd` `miniupnpd` `wscd` `hnapd` `telnetd` `utelnetd` `sshd` `dropbear` `dnsmasq` `dhcpd` `udhcpd` `smbd` `nmbd` `ftpd` `vsftpd` `mosquitto` `sqlite`（作为服务）`ntpclient` `snmpd` `tftpd` `cwmp` `tr069` `l2tpd` `pppd` `openvpn` `hostapd` `wpa_supplicant`
- **符号特征**（对 ELF 用 `nm`/`readelf` 判断）：导入了 `listen`、`accept`、`recvfrom`、`bind`，或导入了 `system`/`popen` 且同时有 socket 相关导入
- **启动链引用**：被 `init.d` / `rcS` 以服务方式拉起且带端口参数（`-p`、`:80`）

### R3 · T1（启动与配置）

```
**/etc/init.d/*, **/etc/rc.d/*, **/etc/rcS, **/rc.local, **/inittab,
**/hotplug/**, **/*.sh, **/etc/config/**, **/*.conf, **/*.cfg,
**/ubi.cfg, **/nvram*, **/default*.cfg, **/etc/passwd, **/etc/shadow,
**/etc/group, **/etc/hosts.allow, **/etc/hosts.deny, **/etc/sudoers
```

理由：启动脚本常以 root 运行、未加引号的变量展开是最稳定的命令注入入口，且配置决定服务是否真正开启（「出厂默认开启」直接决定优先级）。

### R4 · T2（库 / 模块 / 非监听工具）

```
**/*.so, **/*.so.*, **/*.ko, **/usr/libexec/**, **/lib/**, **/usr/lib/**,
**/bin/**、**/sbin/**、**/usr/bin/**、**/usr/sbin/** 中未被 R1/R2 命中的
```

### R5 · T2（保守兜底）

未匹配任何规则的全部剩余可执行/数据文件 → T2，并记录 `fallback: true`，便于复盘「哪些文件落进了兜底」。

**实现顺序**：兜底规则在 `tier-rules.json` 里标记 `fallback: true`，评估时**永远排到最后**（先跑完所有具体规则，仍未命中的才落到 R5）。这样即使 R6 写在数组后面，静态资源也不会被兜底抢走。

### R6 · T3（静态资源与纯数据）

```
**/www/*.html, **/www/*.htm, **/www/*.css, **/www/*.js（非自研，如 jquery/boostrap 等 dist 目录）,
**/*.xml（数据而非配置）, **/*.json（数据）, **/usr/share/**（除 locale/man）
```

### R7 · T3 复核标记

T3 文件若在 Layer 1 命中 P2/P3 → 保持 T3 但 `review_flag=true`，进入「快速人工复核」队列（5 分钟内扫一遍是否有硬编码凭据/调试开关/危险 JS）。

---

## 2. EALB 计算

```python
text_units(f) =  ELF?   section('.text').size / 1024
                脚本/文本?  line_count / 40            # 40 行 ≈ 1KB 代码的认知量
                其他?   0                                # 归 SKIP 或仅关键字扫
weight = {T1: 1.0, T2: 0.5, T3: 0.1, SKIP: 0}
EALB = Σ weight[tier(f)] * text_units(f)
agents = max(1, ceil(EALB / budget))            # budget 默认 800
```

### budget 的取法

| 模型上下文 | 建议 budget | 说明 |
|---|---|---|
| 32K | 300 | 每个 Agent 少分，多轮次 |
| 128K | 800 | 默认 |
| 200K+ | 1500 | 可一次吃下大型 daemon |

### 分片策略

1. 按 `.text` 大小**降序**排序，贪心装箱填满每个 Agent 的预算（先装大的，避免大目标被切碎）
2. **同一二进制不可切分跨 Agent**：一个 `httpd` 的 `main` 与它的 handler 函数必须同一个 Agent 审，否则调用链断在边界
3. 一个 Agent 的分配尽量**同一目录/同一服务栈**，保留上下文相关性（如 `libnvram.so` 与调用它的 `httpd` 同组）
4. 每片都要带上该片涉及文件的 Layer 1 命中摘要，作为「优先验证」提示

---

## 3. 三层审计架构（细节）

### Layer 1 输出格式

```json
{"rule_id":"P0-C-002","priority":"P0","category":"cmd-exec",
 "file":"usr/sbin/httpd","match":"system(",
 "evidence":"@0x2a30  bl system  ; arg from sprintf(buf, \"ping -c 1 %s\", ip)",
 "context_ref":"0x1c40 'ping -c 1 %s'","kind":"binary-string","count":3}
```

`kind` 有两种：`binary-string`（在 ELF 里通过字符串命中，代码层待 Layer 3 确认）与 `source-line`（在脚本/文本里直接命中，附行号）。

### Layer 1 定位的边界（必须向使用者说明）

Layer 1 **只能发现「危险形态的存在」，不能发现「安全控制的缺失」**。以下漏洞类型 Layer 1 全部无法发现，必须靠 Track B：

- 认证绕过、越权（IDOR）、CSRF
- OTA 升级缺签名校验（没有任何「危险函数」，只是少了一个 check）
- 状态机缺陷、竞态条件
- 命令白名单被绕过（白名单「有」，但可以被 `;`/`&&`/换行注入）
- 证书校验被跳过但在配置里而非代码里

### Track B 的入口枚举清单（固件场景专用）

对每个 Tier 文件，Track B 必须产出一份「入口清单」，逐项打勾核查：

| 入口类型 | 枚举方法 | 必查项 |
|---|---|---|
| HTTP/HTTPS | 字符串里的路由（`/cgi-bin/`、`/api/`、`/goform/`）、`httpd` 的 handler 表 | 认证、授权、CSRF、注入、路径穿越、文件上传 |
| SOAP/UPnP | 字符串里的 `urn:`、`AddPortMapping`、`GetExternalIPAddress` | 认证（UPnP 常无）、SSRF、注入 |
| HNAP | 字符串 `HNAP1`、`SOAPAction` | 认证（历史漏洞高发）、注入 |
| Telnet/SSH | 端口参数、`telnetd -l /bin/sh` | 默认口令、后门账号、无认证 shell |
| UDP 协议 | `recvfrom` 调用点、`dnsmasq`、`SSDP`、`mDNS` | 无认证状态、放大攻击、解析溢出 |
| MQTT/CoAP | 字符串里的 broker 地址、topic | broker 认证、topic 通配越权、TLS |
| TR-069/CWMP | `cwmp`、`acs`、`Inform` | 认证、证书校验、URL 可控 |
| 私有 TCP 服务 | 字符串里的 magic、`bind` 端口 | 认证、解析溢出 |
| 蓝牙/NFC 配对 | 相关库与配置 | 配对认证、重放 |
| 本地/物理 | UART、调试口、USB | shell 权限、无口令 |
| 固件升级端点 | 字符串 `upgrade`、`firmware`、`.bin` | 签名校验、路径穿越、降级 |
| 云侧对接 | AWS/Azure/MQTT endpoint、证书 | 证书共享、默认凭据、明文 |

### Layer 3 证据粒度要求

调用链必须逐跳记录，禁止合并：

```
F-001  usr/sbin/httpd  strcpy @0x2a30
  Source : recv() @0x2870 ← HTTP header "Referer" 解析 @0x2894
  跳 1   : sub_2a10(tmp, req)  ; @0x2888 bl sub_2a10
  跳 2   : sub_2a10(buf, p) 里 strcpy @0x2a30（无长度校验，见 @0x2a24 cmp r2,#0x400 后直接调用）
  Sink   : strcpy @0x2a30
  前置   : 未认证可达（认证检查在 @0x2850 beq 分支，仅对 /goform/ 路径生效；Referer 解析在其之前）
```

每跳一个 `文件:偏移`。「未认证可达」这类关键结论必须给出判定依据（哪条分支、哪个比较）。

---

## 4. 置信度阶梯（反幻觉核心）

| 级别 | 定义 | 允许的措辞 |
|---|---|---|
| `confirmed` | 在模拟/真实设备上复现，或有完整可利用链（含绕过缓解措施）证据 | 「可复现」「PoC 如下」 |
| `validated` | Source→Sink 链路静态完整闭合，参数可控性与条件已验证 | 「静态链路完整，条件为…」「未动态验证」 |
| `candidate` | 命中危险形态或疑似缺失控制，但链路中断/条件未确认 | 「疑点」「需确认 X 后才能判定」 |

**对外可见状态：只有 `CONFIRMED` 与 `HYPOTHESIS` 两态。** 内部的三档（`confirmed`/`validated`/`candidate`）在写进报告时收敛成两态，避免读者在「四五个confidence词」里迷路：

| 报告状态 | 由哪些内部级别升入 | 报告的硬要求 |
|---|---|---|
| **CONFIRMED** | `confirmed`（动态复现）+ `validated`（静态链完整闭合、条件已验证） | 必须有完整调用链 + 前置条件 + 证据（反汇编/字节）；标题形如 `F-001 · httpd Referer 头栈溢出`，**标题里不得出现 `(Critical)` 之类评级**（评级进表格字段，不进标题） |
| **HYPOTHESIS** | `candidate`（链路中断/条件未确认） | 必须写明「缺哪一步才能升级」；**不计入漏洞总数** |

**两态 + CVE 三档的关系**：CVE 的 `cve-hit` 天然属于 `HYPOTHESIS`（版本命中，可达性未验证）；`cve-reachable` 升 `CONFIRMED`（静态可达），`cve-exploitable` 升 `CONFIRMED`（动态）。

**HYPOTHESIS 不是「二等公民」**：它对读者最有价值的部分是「还需要验证什么」。强制写「升级所需的关键一步」，把「我觉得这里有问题」变成「我知道该去验证什么」——否则 HYPOTHESIS 就是噪声。

**CVE 命中的独立三档**（与上面三档并行，不互相替代）：

| 状态 | 定义 | 允许的措辞 | 可否计入漏洞数 |
|---|---|---|---|
| `cve-hit` | 仅版本号落在 CVE 影响区间（`mithril --cve` / SBOM 比对） | 「疑似…尚未验证可达性」 | **否** |
| `cve-reachable` | 已在固件内定位受影响代码 + 追出外部可达调用链 + 确认未修复 | 「存在 CVE-XXXX-YYYY，可达路径为…」 | 可（`validated`） |
| `cve-exploitable` | 动态复现或完整利用链 | 「可被利用」 | 可（`confirmed`） |

**禁止清单**（一旦出现即为幻觉，必须回退重写）：

- 没有 `文件:偏移` 的漏洞描述
- 未经 `mithril`/实际扫描得出的 CVE 编号
- 未经反汇编得出的「参数可控」
- 未实际执行的 PoC 代码称为「已验证」
- 把 `mithril --cve` 的组件命中直接写成「设备存在 XX 漏洞」
- **把 `cve-hit`（版本命中）计入漏洞总数、P0/P1 数量或 CVSS 评分**
- **声称「该组件版本受影响 ⇒ 漏洞存在」而不做代码存在性与可达性检查**
- 把 `system()` 字符串命中直接写成 RCE
- 把反编译器（IDA/Ghidra）的伪代码当原文证据引用（伪代码是**推断**，函数边界与变量类型都可能错；证据必须是反汇编/字节）

**空结果的写法**：`NOT_FOUND: 已审计 usr/sbin/httpd(T1, .text 184KB)，覆盖 12 个入口，未发现命令注入/认证绕过/内存破坏；未覆盖：私有 ioctl 语义（需硬件）`。这样写出来的「没找到」才是可复现、可审计的结论。

---

## 5. 覆盖率门禁判据

| 检查项 | 阈值 | 不达标处理 |
|---|---|---|
| T1 文件审计率 | 100% | 阻断出报告 |
| T2 文件审计率 | ≥95% | 未审文件必须逐条给出理由（如「纯 getter 型配置读取」） |
| SKIP 文件关键字扫描率 | 100% | 补扫 |
| `candidate` 处置率 | 100% | 每条必须落到 validated / NOT_FOUND / 待动态验证 |
| `promotions` 跟进率 | 100% | 每个提升都要有 T1 级分析产物 |
| Layer 1 P0/P1 命中复核率 | 100% | 每条 P0/P1 必须有人工/模型明确判定（真/假/待验证） |
| 审阅清单一致率 | 100% | 无 G1/G2/G3 缺口（见下） |
| 报告必填字段 | 9/9 | 缺任一字段视为报告生成失败（见 §8） |

覆盖率计算口径：以「文件」为单位计数，`audited` 的判定标准是该文件在 `30-findings-verified.md` 中出现了至少一条结论（finding 或 NOT_FOUND）。

### 5.1 三方对齐：计划 ↔ 声明 ↔ 结论

**核心问题**：模型在长上下文里会**声称审完了、其实只审了 70-85%**。单看「覆盖率数字」是自证的——模型自己算自己的覆盖率，漏审的文件它自己也不知道漏了。

解法是把三个独立来源对齐：

| 来源 | 文件 | 记什么 |
|---|---|---|
| **计划**（客观，机器产出） | `03-audit-plan.md` | `fw_triage.py` 按 Tier 分片后，**应该**审的全部文件 |
| **声明**（主观，模型产出） | `25-review-list.md` | 模型**自己说**本轮要审哪些、哪些已打勾 |
| **结论**（客观，产物约束） | `30-findings-verified.md` | 实际落盘了结论的文件（finding 或 NOT_FOUND） |

三类缺口：

| 缺口 | 判定 | 说明什么问题 |
|---|---|---|
| **G1 声明未勾选** | `25-review-list.md` 里 `[ ]` 未打钩 | 模型声明要审却没审——**最常见的「假装覆盖」** |
| **G2 计划未声明** | 计划内的 T1/T2 文件不在清单里 | 悄悄缩小范围（回避难文件） |
| **G3 勾选无结论** | 清单打了 `[x]`，但 `30-findings-verified.md` 无该文件结论 | 读了但没落结论（注意力丢失 / 中途忘记） |

**注意 G2 与 T1 覆盖率的关系**：T1 覆盖率是「结论集 vs 计划集」；G2 是「声明集 vs 计划集」。一个模型可能 T1 覆盖率达标（因为把该审的都写了 NOT_FOUND），但清单里压根没声明过某个文件——说明它的「审阅过程」和「结论产出」是脱节的，无法复现。两个检查都要过。

`coverage_gate.py --review-list` 会自动做这个 diff，G1/G2/G3 任一非空即门禁失败。**审阅清单必须逐项打勾**（读完一个文件立刻把 `[ ]` 改 `[x]`），事后补勾等于没审。

### 5.2 审阅清单的写法

```markdown
## S01 · httpd 分片（Agent A）
- [x] `usr/sbin/httpd`
- [x] `usr/lib/libnvram.so`
- [ ] `usr/lib/libcrypto.so.1.1`
```

`coverage_gate.py` 同时认两种行格式（markdown 复选框 / 表格行）：

```markdown
- [x] `usr/sbin/httpd`
| [x] | `usr/sbin/httpd` | T1 |
```

---

## 6. 多 Agent 编排

### 分片与合并

- 每个 Agent 产出独立的 `20-findings-candidates.<shard>.jsonl`，避免写冲突
- 合并时按 `file+offset` 去重，保留**置信度更高**的那条，并在 `dupes` 字段保留另一条的 ID
- 跨片漏洞（如 shard A 的 `httpd` 调用 shard B 的 `libnvram.so`）由**汇总裁剪 agent**单独处理一次，避免两边都以为自己不完整

### 状态文件 schema（关键字段）

`02-tiering.json`:
```json
{"target":"RT-AC1200","ealoc_total":9600,"budget_per_agent":800,"agents":12,
 "tiers":{"T1":[...],"T2":[...],"T3":[...],"SKIP":[...]},
 "promotions":[{"file":"...","from":"T2","to":"T1","reason":"...","finding_ids":["..."]}],
 "shards":[{"id":"S01","ealoc":790,"files":["usr/sbin/httpd","usr/lib/libnvram.so"]}]}
```

`20-findings-candidates.jsonl` 每行一个对象（见 SKILL.md 示例）。

`30-findings-verified.md` 用固定标题层级，便于 `coverage_gate.py` 解析：
```
## F-001 · httpd Referer 头栈溢出
- 文件: usr/sbin/httpd:0x2a30
- 类型: stack-buffer-overflow
- 置信度: validated
- ...
## NOT_FOUND · usr/sbin/dnsmasq
- 覆盖率: 全量
```

`25-review-list.md`（Phase 2.5）逐项打勾，格式见 §5.2。

---

## 7. 时间盒与退出条件

固件审计容易无限深挖。建议时间盒（按目标体量）：

| 目标体量 | Phase 0-2 | Phase 3 | Phase 4 | Phase 5 |
|---|---|---|---|---|
| 小（<5MB，单一 daemon） | 10% | 50% | 25% | 15% |
| 中（5-50MB，路由器/IPC） | 15% | 45% | 25% | 15% |
| 大（>50MB，含 Android/云侧） | 20% | 40% | 25% | 15% |

**退出条件（满足任一即可收敛）**：
1. 门禁全绿
2. T1 已 100% 覆盖，且剩余候选全部为 `candidate` 且已注明「需硬件/需真实设备」
3. 连续两个 Phase 4 迭代没有新增 confirmed

不要在「还没找到 RCE」的焦虑下继续加长 Phase 3——先把已发现的链路验证完再回头扩面。
