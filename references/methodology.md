# 方法论完整定义

本文件定义 Phase 0-5 的判据与算法细节，以及**方法论来源映射**。SKILL.md 给的是骨架，这里给的是可执行的规则。

> **本文件属于 skill 三层架构里的「方法论层」**（决策逻辑、优先级、证据标准、降级策略）。它**不依赖任何具体工具**——换掉解包器、换掉反编译器、换掉仿真器，本文件的判据与算法全部成立。
>
> 与之配套的两层是：**决策判据层**（识别到什么特征走哪条路）与**原子能力层**（单个可调用的操作），都在 `references/atomic-capabilities.md`（§3 判据 / §1–§9 能力清单）。EALB、覆盖率门禁、CVE 纪律、DKTSS 属于本层资产，与工具无关。

## 0. 方法论来源映射

本 skill 把「AI 代码审计 Skill 体系」的设计思路迁移到固件场景。迁移关系如下——理解这张表有助于在遇到新情况时判断「该用哪条原则」：

| 原方法论（Java 代码审计） | 固件场景的等价物 | 为什么这样迁移 |
|---|---|---|
| Phase 0 代码库度量（LOC、Controller 数） | 固件度量：熵扫描、架构、二进制数、`.text` 总量、SUID 面 | 固件没有「文件行数」这个直觉指标，`.text` 才是真实工作量 |
| Tier 分层：Controller / Service / Entity | T1 外部输入入口 / T2 业务与库 / T3 静态数据 | 分层依据从「架构角色」换成「是否可达外部输入」 |
| EALOC = T1×1.0 + T2×0.5 + T3×0.1 | EALB = Σ tier_weight × text_KB | 单位从「行」换成「代码段 KB」，因为固件里二进制占主体 |
| Layer 1：ripgrep + Semgrep 全量预扫描 | `fw_triage.py` + `sink_scan.py` 多语言规则扫描 + mithril 内容扫描 | 固件没有源码语义分析，只能靠字符串/符号/配置模式 |
| Layer 2：双轨审计（Sink-driven / Control-driven） | 扩展为**三轨**：Track A/B 完全保留（固件场景 Track B 权重更高），**新增 Track C 跨请求污点** | 固件认证绕过、无验签 OTA 占比高；且污点常经 NVRAM/IPC/文件**跨请求**传递，单请求视角会系统性漏报高阶漏洞 |
| （Bridge, IEEE S&P'26）高阶污点漏洞检测：BDG + ADG + 跨请求污点 | Track C + `sink-rules.json` 的 `cross-request` 规则 + G6 门禁 | 原方法面向全自动静态分析；本 skill 取其「写-读配对 + 反向溯源」思想，落为可被门禁机械校验的最小集 |
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

### 3.1 绕过假设穷举清单（Track B / T1 第⑧项）

**为什么单列**：「危险调用」靠 Track A 找，「控制缺失」靠 Track B 找。但 Track B 最危险的习惯是——**看到 `if (check_auth(x))` 就写「已鉴权，安全」**。固件里大量真实漏洞恰恰藏在「防护存在但可绕过」：校验比较写错、白名单可被编码骗过、校验对象与使用对象不是同一个。

**触发条件**：只要你在结论里写下「已有防护 / 已鉴权 / 已过滤 / 已验签 / 已限长」——**必须**对该入口跑完 B1–B12，每条给出 `N/A`（附理由）/ `已测·不可绕过`（附证据）/ `可绕过`（升 finding）。**禁止以「有防护」直接收尾。**

| # | 绕过面 | 怎么验证（固件语境） | 真实案例形态 |
|---|---|---|---|
| B1 | 空口令 / 缺省口令 | 找认证函数的**早返回**与**空值分支**；口令字段缺失 ≠ 为空串，两者常走不同分支 | 登录页不填密码直接提交；`strcmp(pw,"")==0` 通过 |
| B2 | 默认 / 硬编码凭证 | `mithril --secrets` + 字符串搜 `default_passwd`/`super_password`/`factory`；常量串比对（非哈希）即可用 | 出厂通用口令、调试后门账号、`admin/admin` |
| B3 | 认证覆盖缺口 | 枚举 `no_auth`/`skip_auth`/白名单表；**按 HTTP 方法分别测**（GET 免鉴权、POST 鉴权是经典设计缺陷）；后缀/前缀豁免 | `/goform/` 需鉴权，但 `/cgi-bin/` 同级接口不需 |
| B4 | 前缀匹配绕过 | 定位 `strncmp`/`strstr`/`startswith` 的匹配位置与长度；构造能「匹配前缀但落到别处」的路径 | `/cgi-bin/diag.cgi` 是白的 → 用 `/cgi-bin/../etc/...` 绕过 |
| B5 | 路径穿越变形 | 逐个试变形：`../`、`..\`、`%2e%2e%2f`、`..%c0%af`、双重编码、绝对路径、尾随 `.`/空格、长路径截断、软链接 | Zip Slip；升级包内 `../../etc/passwd` |
| B6 | 大小写 / 编码 / 规范化 | 比较是否大小写敏感、FS 是否敏感（通常不敏感→可绕过）；`%00` 截断；UTF-8 overlong；Unicode 归一化 | `../` 被过滤但 `..%2f` 未过滤 |
| B7 | 参数污染（HPP） | 同名参数重复时，**校验函数取哪个、使用函数取哪个**；`&a=1&a=2`；数组参数；「缺值」vs「空值」 | 网关校验取第一个、后端取最后一个 |
| B8 | 边界 / 截断 | 找 `>` vs `>=`、signed/unsigned 比较、`strncpy` 不补 `\0`、`strlen` 之后长度被改、整数溢出绕过上限检查 | 长度检查 `if (len > 0x100)` 但 `len` 是 signed |
| B9 | 白名单命令注入 | 白名单「有」不代表安全：查参数是否被拼进 shell；试 `;` `&&` `\|` 换行 `` ` `` `$()`；参数位注入（`-o`、引号逃逸） | `ping` 白名单，但 IP 参数未过滤 `;` |
| B10 | 时间窗口 / 竞态（TOCTOU） | 校验路径 vs 打开路径是否同一个；检查后被替换的窗口；令牌验证后是否可变；并发绕一次性检查 | 上传临时文件校验后、执行前被替换 |
| B11 | 状态 / 顺序绕行 | 未初始化状态是否被信任；能否跳过前置步骤直调后置接口；重放；恢复出厂后是否残留 | 未登录直调「已登录才该能调」的接口 |
| B12 | 校验对象 ≠ 使用对象 | 列出「校验了什么」与「用了什么」，若不一致即可绕：`Host` vs `X-Forwarded-Host`；前端文件名 vs 后端字段；验签 A 却加载 B；查一个 header 却信任另一个 | ISAPI/代理场景的 Host 校验绕过 |

**产出格式**（写进该文件结论的 `bypass_matrix`）：

```yaml
entry: /cgi-bin/ipv6_disable.cgi
existing_control: "is_authorizied() 校验 board_id"
B1: N/A (无口令面)
B2: N/A
B3: 可绕过 → finding F-012 (handler 表未在鉴权白名单内)
B5: 已测·不可绕过 (证据: 路径经 realpath 后再比对)
B9: 可绕过 → finding F-013 (wan_ifname 未过滤即拼 system)
upgraded_findings: [F-012, F-013]
```

### 3.2 跨请求污点（高阶漏洞）与 Track C

> 方法来源：**Bridge: High-Order Taint Vulnerabilities Detection in Linux-based IoT Firmware**（IEEE S&P 2026；Peng / Liu / Cheng 等，中科院信工所 + 国科大 + 蚂蚁 + 清华；artifact 见 Zenodo `10.5281/zenodo.17232400`，Docker `pjqwudi123/bridge:1.0`）。本 skill 取其中「**写-读配对 + 反向溯源**」的最小可用子集，落为规则 + 门禁。

**问题**：`sink-rules.json` 与 Track A 追的都是**单个请求内**的 source→sink。但固件里最高频的一类是**跨请求污点漏洞（high-order taint vulnerability）**——污点在请求 A 写入持久化存储，在请求 B 才被读出并触发 sink。写面与读面常常：

- 分处不同**请求**（不同动作关键字 / 不同 URL）；
- 分处不同**进程**（前端 `prog.cgi` 写，后端 `rc` / 守护进程读）；
- 经由**持久化存储**中转（NVRAM、`/tmp` 文件、IPC 控制消息）。

只审单请求会得出「该值在本进程内没有写入点 → 不可控」的错误结论，整条链被漏掉。

**术语对齐**：

| Bridge 术语 | 含义 | 本 skill 的对应 |
|---|---|---|
| 高阶污点漏洞 | 需多请求协同、经持久化存储传递的可控输入漏洞 | Track C 的目标物 |
| AEH（Action Entry Handler） | 请求动作关键字对应的处理入口 | `entrypoints.json` 的 `handlers[]`（`.cgi → sub_xxx`） |
| IPF（Input Parsing Function） | 解析用户可控数据的污点源函数 | Track A 的 source（`websGetVar`/`recv`/`nvram_get`…） |
| BDG | 二进制间污点传播图 | 跨二进制调用链（Track A 的跨文件延伸） |
| ADG | 动作处理函数间的跨进程控制依赖图 | 写面 ↔ 读面的配对图（Track C 产出） |

**持久化存储 4 类**（= 跨请求通道）：NVRAM / uci 键、运行时文件（`/tmp`·`/var`，含符号链接）、IPC（socket / 控制消息）、进程环境。

**Track C 流程（写-读配对 + 反向溯源）**：

1. **枚举写面**：`sink-rules.json` 的 `cross-request` 规则（`P1-T-001/002`、`P2-T-001/002`）在 Layer 1 标出持久化写入点；逐点记 `{存储, 键/路径, 写 API, 调用者(入口), 值是否用户可控}`。
2. **配对读面**：对每个写面，全量检索谁读同一键 / 路径并送入 sink（字符串锚点 → xref → 调用者）。写面与读面不在同一请求是**常态**，不是「不可控」的理由。
3. **反向溯源闭合**：`store → 写面(入口/请求) → 读面(sink)` 三段齐备，且写面满足「用户可达 ∧ 值可控 ∧ 无白名单」时，方可判 `CONFIRMED`；**写面缺失 → 只能 `HYPOTHESIS`**。

**静态枚举的边界**：控制消息关键字常被动态拼接（`str_merge` / `snprintf`，如 `"lan0_" + "management_link"`），纯字符串匹配会漏检——必须按 Layer 3 反编译回溯拼接点（即 Bridge 的 OD-ICP：按需过程间常量传播）。

**门禁判定（G6 / G7）**：

`coverage_gate.py --cross-request`（G6）扫描报告每条 finding 的 `Source:`：

- 命中 `CROSS_REQUEST_SOURCE`（`nvram`/`uci` 键，或 `/tmp`·`/var`·`/dev/shm`·`/mnt`·`/data`·`persist` 路径）→ 该 finding **必须**含 `WRITE_FACE` 标记（`写入面`/`写端`/`write-face`/`可写`/`被写入`/`由…写入`/`导入`/`restore`/`nvram_set`…）；
- 缺 → **fail**。静态配置（镜像内 `.conf`/`.cfg`）**不触发**——避免把「版本内固定配置」误当跨请求污点。

`coverage_gate.py --taint-graph`（G7）进一步查**图**是否成立。G6 只认文字，文字可以含糊（写一句「由恢复配置导入」就过了），所以必须再问五个问题：

1. **写它的请求与触发这次读的请求是不是同一个？** 相同 → **一阶**，不得计入高阶。⚠️ 注意比的是**触发 action**，不是读点的宿主进程——读点几乎总在 `rc`/`librcm.so`，拿它当「action」会把一阶全部算成高阶。DIR878 实测：`SysLogRemote_IPAddress` 与 `lan0_management_link` 都带 `other_get`、读点都在 `rc`，但前者 set 与 trigger 同为 `SetSysLogSettings`（一阶），后者是 `SetNetworkSettings` 写、`SetVLANSettings` 读（高阶）。
2. **键在两端是不是同一个字面量？** 不一致 → 常量恢复没做（OD-ICP 缺环），配对无效。
3. **读面到 sink 真实可达吗？** 「读到了」不等于漏洞——必须给出 sink 地址与类型。
4. **两端有没有地址与证据？** 没有就无法复核，等于没做。
5. **读点在别的进程时，哪个控制值把请求带过去？** 缺 `via_control` → 「请求 2 能到达读点」只是假设（ADG 边缺失）。

图由 `scripts/taint_graph.py` 生成（`recover` 恢复常量键 → 补读写点 → `build` 构图），方法全貌见 **`references/high-order-taint.md`**。strict 档位下，报告一旦声称存在高阶漏洞，缺图即失败。

**已验证范例（RAXE500）**：`wan_ifname` 在 httpd 内全量 xrefs **只读零写** → 唯一写面锁定到「上传恢复配置 → `shared_acos_nvram_restore_configuration` 无键名白名单导入」→ 读面 `sub_11133C`/`sub_1114D4` 的 `system("ifconfig %s …")` → `F-012`（同源 `F-013`）。这条链在只审单请求时被判为「不可控」而漏掉。

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

### 5.1.1 缺口检出后的修复路径（自动 / 人工）

检出 G1/G2/G3 **不等于一律要人工介入**——按缺口性质分流（与 `SKILL.md` Phase 2.5 一致）：

| 缺口 | 自动修复？ | 理由 | 动作 |
|---|---|---|---|
| **G1 声明未勾选** | ✅ **自动** | 范围**已声明**，只是没执行完 | 重派缺失文件给同 shard；原 Agent 结束则新起「补审」Agent（只带该文件 + Layer 1 摘要 + shard 上下文） |
| **G3 勾选无结论** | ✅ **自动（限 1 轮）** | 文件**已被读过**，只差落结论 | 重跑「结论汇总」；仍无结论 → 升级人工 |
| **G2 计划未声明** | ❌ **禁止自动** | 这是**范围被缩小**，属范围决策；自动补回会掩盖问题 | 只能「补充分片重审」或「书面 waiver」，且必须在报告中留痕 |

**自动化红线**：

1. 自动修复**只允许补执行 / 补汇总**，**不得改变审阅范围**（G2 尤其禁止自动）。
2. 每轮修复写 `40-coverage.md` 的 `auto_recovered` 段（缺口类型 / 文件 / 轮次 / 结果）；**缺口留痕永久保留**，不允许「修完即消失」。
3. **最多 2 轮自动修复**；第 3 轮仍有缺口 → 强制人工 + 门禁阻断。
4. 机器**不得生成 finding 结论**，只能整理已有产物。

**门禁开关（已实现）**：

```bash
coverage_gate.py --auto-recover [--max-rounds 2] [--recover-round N]
```

缺省仍是**只检出（保守）**。开启后：G1 → `reassign`，G3 → `reconclude`，G2 → `blocked_manual`（永不自动）。轮次超限（`--recover-round > --max-rounds`）→ G1/G3 亦回硬门禁。计划同时写入 `40-coverage.auto-recover.json` 供编排层消费：

```json
{"round": 1, "max_rounds": 2, "budget_exhausted": false,
 "reassign": [{"file": "usr/sbin/upnpd", "action": "re-dispatch", "stage": "补审"}],
 "reconclude": [{"file": "usr/sbin/ghost", "action": "re-summarize", "stage": "结论汇总"}],
 "blocked_manual": ["usr/lib/libnew.so"]}
```

G2 的 waiver 落在 `25-review-list.md` 的 `## WAIVER` 段，格式：

```markdown
## WAIVER
- `usr/lib/libfoo.so` — 纯第三方二进制，无外部输入面，版本已由 SBOM 记录 (@审计负责人)
```

门禁与报告都要能读到 waiver，并把它计入「未覆盖项 + 理由」。

### 5.1.2 四条深度门禁（G4 / G5 / G6 / 类型→Base）+ 高阶链图（G7）

覆盖率门禁原本只回答「**每个文件**有没有结论」。这在 2026-10 的 RAXE500 审计上暴露了系统性问题：`usr/sbin/httpd` 有结论 → 文件级 100% PASS，但它 **2923 个函数只精读了 5 个、167 个 CGI handler 一个没读**，漏掉一条认证后 root 命令注入（`ipv6_disable.cgi` → nvram `wan_ifname` → `system("ifconfig %s mtu %d")`）——而且这条链是**跨请求**的（写面在上传恢复配置、读面在 ipv6 CGI），单请求视角根本看不到（§3.2）。为此新增四条门禁，把风险单位从「文件」提升到「**入口 / 断言 / 跨请求来源 / 类型**」。

**G4 入口级覆盖**（`--entrypoints <entrypoints.json>`）

- 适用：**T1 且 `text_kb > 200` 的服务型可执行**（`bin|sbin|usr/bin|usr/sbin` 下的 ELF，排除 `.so`）。阈值用 `--text-kb-threshold` 调。
- 每条记录：`handler_table_count`（权威派发表条目数）+ `handlers[]`（每条含 `name` / `addr` / `conclusion`）。
- 判据：①有记录；②`len(handlers) ≥ handler_table_count`；③**每个入口 `conclusion` 非空**（finding id / `NOT_FOUND` / `待动态验证`）；④全局入口审计率 ≥ `--entrypoint-audit-min`（默认 100%）。
- 豁免只有两条且留痕：文件级 `waiver{reason}`，或 `entrypoints:"none"` + `reason`（CLI 工具是 sink 不是 source）。
- 显式给了 `--entrypoints` 却找不到文件 → **判失败**（不交枚举不能比交了不全更容易过）。
- 骨架生成：`scripts/entrypoints_init.py --tiering 02-tiering.json --out entrypoints.json --merge entrypoints.json`。

**G5 绕过矩阵完备**（`--bypass-check`，扫 `30-findings-verified.md`）

- 触发：任一章节正文出现**防护断言**——`已鉴权/已认证/已过滤/已验签/已限长/有防护/已做校验/存在性校验/白名单校验/长度校验/字符校验/不可利用`（前置否定词 `未/无/不/非` 会排除「未鉴权」「无过滤」）。
- 「修复建议」行是建议不是断言，扫描时剔除。
- 要求：该章节须出现 `bypass_matrix` 或 ≥10 个 `B1..B12` 条目号。
- 语义：**「有防护」≠「防护有效」**——这正是 B1–B12（§3.1）的机械化落点。

**G6 跨请求污点溯源**（`--cross-request`，扫 `report.md`）

- 触发：finding 的 `Source:` 命中 `CROSS_REQUEST_SOURCE`——`nvram`/`acosNvramConfig`/`nvram_safe_get`/`nvram_get`/`uci` 键，或 `/tmp/`·`/var/`·`/dev/shm`·`/mnt/`·`/data/`·`persist` 路径。
- 要求：该 finding 正文须含 `WRITE_FACE` 标记（`写入面`/`写端`/`write-face`/`可写`/`被写入`/`由…写入`/`导入`/`restore`/`nvram_set`…）。
- **静态配置不触发**：镜像内 `.conf`/`.cfg`（如 RAXE500 `F-002` 的 `updater.conf`）不是运行时写入，不纳入——避免误报。
- 语义：污点可跨请求经持久化存储传递（Bridge, IEEE S&P'26，§3.2）。**写面缺失 = 溯源未闭合 = 「输入可控」不成立**。
- 实测：RAXE500 报告 5 条持久化来源（F-003/004/006/012/013），均声明写入面 → PASS。

**类型 → DKTSS Base 命中**（`--type-base`，默认告警 / `--type-base-strict` 硬门禁）

- 报告里每个 `类型:` 标签（用 `/`、`、`、`,` 拆分，去掉 CWE 括注）须能经 `BASE_SYNONYM` 关键词归一到 Base 表某一行；不能则须写「映射依据」，否则列出。
- 噪声控制：实测 RAXE500 报告 17 个标签仅 3 个未命中（`更新流程降级`、`MITM`、`不安全临时文件`）→ 这 3 个正是 Base 表的真实落空点，已补 2 行（`传输安全降级 / MITM`、`不安全临时文件 / 本地提权`）。

**门禁档位**：上面四条高阶门禁（`--entrypoints` / `--bypass-check` / `--cross-request` / `--type-base-strict`）在 `standard` 档位下仍是**按需开启**，但只要没开，检查项在 `gate-config.json` 里就是 `SKIPPED` 而不是 `PASS`——**「没跑」和「通过」必须能区分**，只读退出码是分不出来的。

要一次全开用 `--profile strict`：四条高阶门禁全部强制启用，且**未执行的必需检查项直接判失败**（`required SKIPPED → FAIL`）。Phase 5 的标准命令即带 `--profile strict`。复现性由 `gate-config.json` 承担——它记录档位、`GATE_VERSION`、各项阈值、各项 `status`，以及全部输入文件的 sha256，事后可校验「当时的判定是在什么输入上、用什么口径做出来的」。

回归由 `scripts/selftest.py` 的 `[13/15] 扫描完整性与门禁严格性` 组覆盖（含 standard vs strict 的 SKIPPED 行为差异）；**文档与 CLI 的一致性**由 `[14/15]` 组对拍——它把 `README.md` / `SKILL.md` / `references/` / `assets/` 里每条 `scripts/*.py` 示例命令的 `--flag` 与脚本 `--help` 逐一对齐，并检查布尔开关没被当成带值参数（历史缺陷：`--tier` 是 `store_true`，文档却写成 `--tier <rootfs>`，照抄即报错，而单元测试全绿）。


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
