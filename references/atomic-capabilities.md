# 原子能力清单与决策判据

## 0. 本文件在 skill 三层架构中的位置

本 skill 固化的**不是「完整工具」，而是三层能力**。请先建立这个心智模型，再往下读：

| 层 | 固化什么 | 承载文件 |
|---|---|---|
| **方法论层** | 决策逻辑、优先级、证据标准、降级与交付规范 | `SKILL.md` 七条铁律 · `references/methodology.md`（EALB / 三轨审计 / B1–B12）· `references/reporting.md`（DKTSS / 工作简报 + 7 个技术区块） |
| **决策判据层** | **识别到什么特征 → 走哪条路**（含失败信号与回退条件） | **本文件 §3**（Phase 1 提取选路树、Phase 4 仿真选路树） |
| **原子能力层** | **单个可调用的操作**（能力、实现方式、输入输出） | **本文件 §1、§4–§9** |

**Agent 的工作流是：侦察 → 判断 → 调用原子能力 → 观察反馈 → 按反馈调整策略。**
不是「按顺序试工具」，也不是「调一个完整工具让它跑完」。

### 0.1 为什么整链自动化工具不能当主路径

FAT / Firmadyne / FirmAE / EMBA / FACT 这类工具的本质，是**把一整套决策流程固化成了脚本**：

- **FAT / Firmadyne**：提取 → 打包镜像 → 跑 QEMU → 网络可达 → 结束。每一步都是启发式规则，遇到非常规固件（非标分区表、私有 U-Boot、UBIFS、内核裁剪、多级 squashfs 嵌套）就卡在某一环。
- **EMBA**：提取 → 静态扫描 → CVE 比对 → 报告。不管分析的是什么设备，跑的是同一套规则。

它们的「成功率」是用大量启发式修补堆出来的，**依赖问题、兼容性问题、内核匹配问题都是这个设计模式的副产品**。更关键的是：**它们在替 Agent 做决策**——而设备是 ar71xx 还是 ipq40xx、文件系统是 squashfs 还是 UBIFS、内核是 4.14 还是 5.10、用户态是 BusyBox 还是完整 coreutils，这些差异恰恰决定了分析路径。

> **定式**：整链工具只有一个合法位置——**跑通主路径之后，用作交叉验证基线**（§10.2）。它不是 Phase 1/4 的主路径，且它的输出必须按「线索而非结论」处理（见 SKILL.md 铁律 7 与 `references/reporting.md` 第 ⑥ 区块）。

### 0.2 本文件怎么读

- 要**查某个能力的具体命令** → 直接跳到 §4–§9。
- 要**决定下一步做什么** → 看 §3 的决策树；那里才是本文件的核心。
- 某个能力**跑不起来** → 看 §11 的替代路径矩阵，并注意「替代是否保结论强度」这一列。

---

## 1. 本机工具基线（优先使用，非 GNU 对应物）

分析过程中凡是「在**我自己的机器上**查文件 / 搜内容 / 跑 Python」，一律按下面的优先级，**不要默认用 `find` / `grep` / `pip`**：

| 场景 | 首选 | 替代（缺失时） | 要点 |
|---|---|---|---|
| **查找文件** | **`fd`**（Rust 重写 find） | `find` | 语法短、默认忽略 `.gitignore` 与隐藏项、并行遍历 |
| **过滤内容** | **`rg`**（ripgrep） | `grep` | 默认跳过二进制与 `.gitignore`、自动多线程、`-uu` 关忽略、`-t py` / `-g '*.sh'` 限类型 |
| **结构化代码搜索** | **`sg`**（ast-grep） | `rg` + 正则 | 按语法树匹配，跨语言、不受格式/换行影响；适合「找所有 `strcpy` 的第二参是否为常量」这类问题。**本体也是 Layer 1 的结构级二次过滤引擎**（见 §2.3 C6 / §3.3），命令名 `ast-grep` 或 `sg` 均可 |
| **源码级污点 / 结构匹配** | **`semgrep`** | `sg` + 人工三跳追链 | 支持跨函数污点（taint mode），用于 Phase 3 对**源码类目标**自动追 source→sink；对剥离符号的 ELF **不适用**（见 §5.2） |
| **Python 环境** | **`uv`** | `venv` + `pip` | `uv venv` / `uv pip install` / `uv tool install` / **`uvx` 免安装直跑** |

```bash
# 查找文件：fd 而不是 find
fd -e c -e h -e sh                       # 按扩展名
fd -t f -H 'passwd|shadow'               # 含隐藏项
fd -e so -x readelf -d {}                # 对每个结果执行命令
fd . rootfs/etc -t f --max-depth 2       # 限定目录与深度

# 过滤内容：rg 而不是 grep
rg -n 'system\s*\(' -t c -t cpp          # 按文件类型
rg -uu 'password'                        # 连二进制与忽略项一起搜
rg -l 'upgrade' --glob '*.sh'            # 只要文件名
rg -A3 -B3 'strcpy'                      # 带上下文
rg --files-with-matches 'telnetd' rootfs # 定位到文件

# 结构化搜索：ast-grep
sg -p '$F($A, $B)' -l c                  # 双参函数调用
sg -p 'system($ARG)' -l c                # 所有 system 调用及其实参
sg -p 'eval $$$ARGS' -l bash file.sh     # shell 真调用（不匹配注释/字符串）

# 源码级污点：semgrep（仅源码类目标）
semgrep -e 'system(...)' --lang php --json file.php
semgrep --config taint-rule.yaml --json rootfs/webs   # taint mode 需 YAML 规则

# Python：uv 而不是 pip / venv
uv venv .venv && source .venv/bin/activate
uv pip install unblob qiling
uv tool install binwalk                  # 装 CLI 工具
uvx ida-mcp stdio                        # 免安装直跑，不污染环境（可加 --agent <名称> 记录会话调用方）
uv run script.py                         # 用项目环境跑
```

> **重要边界**：这条规则只适用于**本机**（分析工作站）。一旦进入提取出的 rootfs，里面跑的 `grep`/`find`/`sh` 是**目标设备的 busybox 命令**——那部分不能换成 `rg`/`fd`，也不要用 `--include` 这类 GNU 扩展（busybox 不支持）。判断标准：这条命令是**我在自己机器上执行**，还是**在目标文件系统里执行**。

> 缺失时的处理：`fd`/`rg` 没装就用 `find`/`grep` 兜底，但**在报告与回复里显式注明降级**，不要静默替换——否则后人复现时命令对不上。

**环境矩阵**（决定用哪条执行通道）：

| 环境 | 适用性 | 说明 |
|---|---|---|
| Linux 发行版（Kali / Ubuntu） | ★★★★★ | 全部能力原生可用 |
| Docker | ★★★★★ | 推荐。unblob 官方镜像自带全部解包器；`docker run --rm -v "$PWD:/data" -w /data ghcr.io/onekey-sec/unblob:latest /data/firmware.bin` |
| WSL2 | ★★★★ | 可用，注意 `/mnt/c` 上执行大文件解包会慢 |
| AttifyOS / EmbedOS / IoT Pentesting OS | ★★★★★ | 预装 Attify 全家桶 |
| Windows 原生 | ★★ | 只有本 skill 的五个 Python 脚本能原生跑；其余走 Docker 或 Linux 主机 |

---

## 2. 原子能力总表

> 「实现方式」是可以替换的；「能力」与「输入 → 输出」是稳定的。**做决策时认能力，不认实现。**

### 2.1 侦察与定界（Recon）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| R1 | **固件格式识别** | `file`、`binwalk`（仅识别）、magic bytes 手工核对 | 固件文件 → 格式/容器/疑似的 rootfs 偏移 |
| R2 | **熵分布扫描** | `moria -E`、`binwalk -E`、`binwalk -Me` | 固件文件 → 高熵区/未识别区边界（判加密/压缩的依据） |
| R3 | **头部与分区解析** | `binwalk` chunk 列表、厂商升级包格式识别、`dd` 按偏移切 | 固件文件 → 分区表/头部字段/各段起止 |
| R4 | **版本与型号提取** | `rg` 扫 `VERSION`/`build`/`model`/`fw_ver`、`strings` | 固件/rootfs → 型号、固件版本、构建时间 |

### 2.2 提取（Extract）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| E1 | **递归解包** | `unblob`（78+ 格式，chunk 起止精确，未知块也 carve） | 固件文件 → 完整产物树 + JSON 报告 |
| E2 | **SquashFS 解包** | `unsquashfs`（需 sasquatch 版支持非标压缩）、`moria -e` | squashfs 段/镜像 → rootfs 目录 |
| E3 | **UBI / UBIFS 解包** | `ubireader_extract_images`、`ubi_reader`、`moria -e` | UBI 镜像 → UBI 卷 → rootfs 目录 |
| E4 | **JFFS2 解包** | `jefferson`、`moria -e` | JFFS2 段 → rootfs 目录 |
| E5 | **ext / F2FS / EROFS / cramfs / romfs** | `debugfs -R rdump`、`dump.f2fs`、`fsck.erofs --extract`、`cramfsck -x`、`moria -e` | 文件系统镜像 → rootfs 目录 |
| E6 | **内核提取** | `binwalk -e`、按 R3 偏移 `dd`、FIT/uImage 头部解析 | 固件文件 → `vmlinux` / `Image` / `zImage` / `uImage` |
| E7 | **DTB / bootargs 提取** | `dtc -I dtb -O dts`、从 uImage 解出 appended DTB、`strings` 找 `bootargs` | 内核镜像/固件 → 设备树、内核命令行（决定 root= 与 mtdparts） |
| E8 | **内核符号恢复** | `vmlinux-to-elf` | 剥离符号的内核镜像 → 带符号 ELF（可 `nm`/`objdump`） |
| E9 | **加密固件判定与解密** | 熵 + 魔数 + 头部规律判据（见 §3.1 E 分支）、固件内找解密函数/密钥、FCC ID / 官方工具交叉 | 无法识别的固件 → 明文固件 或「已判定加密」的记录 |

### 2.3 内容级扫描（Content）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| C1 | **凭据 / 密钥 / 哈希扫描** | `mithril --secrets`（确定性阶梯 pattern→structural→validated） | rootfs → 泄露凭据、私钥、JWT、弱口令标记 |
| C2 | **SBOM 生成** | `mithril --sbom -C out/`（CycloneDX + SPDX） | rootfs → 组件清单 |
| C3 | **组件 CVE 比对** | `mithril --cve`（离线本地镜像，带 CISA KEV / EPSS） | rootfs → 版本区间命中（**只有 cve-hit，非漏洞**） |
| C4 | **启动与信任姿态** | `mithril --boot`、`--keys` | rootfs / BIOS → U-Boot env、Secure Boot 姿态、公钥弱点 |
| C5 | **许可证与文件来源** | `mithril --licenses` | rootfs → 许可证清单与文件位置 |
| C6 | **源码 / 脚本结构级扫描（二次过滤）** | `ast-grep`（`sg`）/ `semgrep`，由 `sink_scan.py` 的 `structural` 规则驱动 | 正则命中的脚本/web 文件 → 结构确认后的真实调用点（剔除注释/字符串误报）；对剥离符号的 ELF **不适用**（见 §3.3 / §5.2） |

### 2.4 文件系统侦察（FS Triage）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| F1 | **文件类型清单** | `fd -t f -x file {}` | rootfs → 类型分布（定位 ELF / 脚本 / 数据库） |
| F2 | **SUID / SGID 与权限异常** | `fd` + `test -u/-g`、`fw_triage.py`（Windows 上权限位不可靠时用它） | rootfs → 提权面清单 |
| F3 | **启动链读取** | 读 `etc/init.d/*`、`rc.d`、`inittab`、`rcS`、`rc.local`、`hotplug`、`/etc/config/*` | rootfs → **攻击面地图**（谁真正在跑） |
| F4 | **动作关键字枚举** | `rg -o -N '"[A-Z][A-Za-z0-9_]{3,}"' web/ \| sort -u` | Web 前端 / 脚本 → 请求动作名 → 入口文件/二进制的映射 |
| F5 | **硬编码凭据与 URL 面** | `rg` 规则集 + `mithril` | rootfs → 云侧对接面、后门口令 |
| F6 | **NVRAM / 配置键面** | `strings` 扫 `nvram_get`/`nvram_set` 的键名常量、`/etc/config/*` | rootfs → 可写持久化键清单（Track C 种子） |

### 2.5 二进制分析（Binary）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| B1 | **架构与 ABI 识别** | `readelf -h`（Machine/Class/Data/e_flags）、`file` | ELF → 架构、端序、浮点 ABI（决定用哪种 qemu/仿真后端） |
| B2 | **符号与导入表** | `readelf -s -d`、`nm -D --undefined-only`、`strings -a -t x` | ELF → 危险符号及其调用点候选 |
| B3 | **危险符号与调用点定位** | `radare2`（`axt @ sym.imp.system`）、`fw_triage.py`、`sink_scan.py` | ELF → sink 站点清单（含实参形态：字面量/`%s`/间接） |
| B4 | **反编译与 xref 追链** | IDA MCP（`execute_python` + `ida-domain`）→ Ghidra 无头 → radare2 手工 → `objdump`+`strings` | ELF + 地址 → 调用链（字符串锚点 → 引用点 → 调用者） |
| B5 | **分发入口表枚举** | 找 `.cgi`/`.asp` 名表与函数指针数组（`fat handler-table`、自写 IDAPython/radare2 脚本） | ELF → 「URL 路径 → 处理函数」全表（**覆盖率门禁 G4 的依据**） |
| B6 | **数据流 / 污点追踪** | 人工三跳追链 + IDA MCP、`fat taint --sink-candidates` | 二进制 + sink 地址 → source→sink 路径或「不可达」结论 |
| B7 | **跨请求污点配对** | 写面枚举（§2.4 F6）→ 读端枚举 → 反向溯源（见 SKILL.md Phase 3 Track C） | NVRAM 键改写点 + 读入点 → 跨请求链 |
| B8 | **二进制比对定位补丁** | `BinDiff` / `Diaphora` / `Ghidriff`、`fat inspect update` | 旧版 + 新版固件 → 差异函数 → 疑似被修漏洞（⑥→④ 的入口之一） |
| B9 | **FLIRT / 库函数识别** | `db.signature_files.apply(sig)`、Ghidra FID | 剥离符号的 ELF → 识别出的库函数（降低分析量） |

### 2.6 动态验证（Dynamic）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| D1 | **整机启动** | `qemu-system-{arm,mips,mipsel,aarch64}` + 提取的内核/DTB/rootfs | 内核 + rootfs + bootargs → 串口启动日志 |
| D2 | **启动失败诊断** | 读串口输出 / dmesg，按 §3.2 的失败分支定位（panic 原因、缺失设备、init 失败） | 失败日志 → 针对性修补点 |
| D3 | **rootfs 可挂载性修补** | 改 `init`、补 `/dev` 节点、stub 掉硬件依赖、换 `root=`/`mtdparts` | rootfs → 可启动 rootfs |
| D4 | **服务可达性探测** | 在隔离网络内 `nmap`/`curl`/`nc`，比对 `F3` 启动链确认的服务 | 运行中的固件 → 真实开放端口与 HTTP 路由 |
| D5 | **单二进制运行** | `qiling`（`qltool run -f ./bin --rootfs ./rootfs`）、`qemu-user` + `chroot` | ELF + rootfs → 执行结果/退出码 |
| D6 | **依赖打桩** | Qiling Python API 里替换 `nvram_get`/`ioctl`/`watchdog` 等私有接口 | 缺失依赖的 ELF → 可继续执行的上下文 |
| D7 | **sink 参数真值观测** | `ql.hook_address()` 在 sink 入口读寄存器/内存 | 二进制 + sink 地址 + 输入 → **实参真值**（把 HYPOTHESIS 变 CONFIRMED） |
| D8 | **系统调用 / 文件访问追踪** | `qemu-user -strace`、`strace -f`、`ltrace`、Frida | 运行中的二进制 → syscall/库调用序列 |
| D9 | **覆盖率采集** | Qiling `--coverage-format drcov`、AFL++ 的 map、`cov-analysis` | 运行的二进制 + 输入集 → 覆盖了哪些函数 |
| D10 | **模糊测试** | `afl-fuzz -Q/-U/-O`、`honggfuzz`、`libFuzzer` | 二进制/harness + 种子字典 → 崩溃样本 |
| D11 | **崩溃 triage** | 逐个用 `qltool`/`gdb-multiarch` 复现，判 PC 是否可控 | 崩溃样本 → 可控性结论（**DoS 不等于 RCE**） |
| D12 | **插桩与动态调试** | Frida、`gdb-multiarch`、`ret-sync`、Qiling `--gdb` | 运行中的进程 → 运行时状态 |

### 2.7 网络与协议（Network）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| N1 | **端口与协议指纹** | `nmap -sV`、协议专属库 | 目标 → 服务/协议清单 |
| N2 | **协议客户端与重放** | MQTT/CoAP/UPnP 客户端工具、`RouterSploit`、`expliot`、`boofuzz`、`Scapy` | 协议端点 → 请求/响应/畸形输入 |
| N3 | **流量拦截代理** | `mitmproxy`、`IoXY`（MQTT）、Burp | 客户端 ↔ 云端 → 明文请求与凭据 |
| N4 | **主动情报查询** | Shodan / Censys / ZoomEye / FCC ID Database | 型号/指纹 → 暴露在公网的同类设备面 |

### 2.8 硬件接口（Hardware，需物理接触）

| # | 原子能力 | 实现方式 | 输入 → 输出 |
|---|---|---|---|
| H1 | **UART 控制台** | 万用表找 GND/TX/RX → `screen /dev/ttyUSB0 115200`（试 9600/38400/57600/115200）；U-Boot 阶段打断改 `bootargs` | 硬件 → root shell / U-Boot 提示符 |
| H2 | **SPI NOR 读取** | CH341A + `flashrom -p ch341a_spi -r dump.bin`（先认丝印） | 硬件 → 固件 dump |
| H3 | **eMMC / JTAG / SWD** | 读卡器或 ISP 引脚；`JTAGulator` 找引脚 + `OpenOCD` + GDB；`pyOCD` + ST-Link/J-Link | 硬件 → 全片 flash / 内存读写 |
| H4 | **故障注入** | ChipWhisperer（电压/时钟毛刺、功耗分析） | 硬件 → 绕过校验/提取密钥 |

---

## 3. 决策判据（本文件核心）

> 判据层的职责：**给定侦察结果，输出「下一步调哪个原子能力」**，并规定**什么反馈意味着该换路**。
> 关键差别：**看反馈去修，而不是失败就换下一个工具重跑。** 换工具是最后手段，不是第一反应。

### 3.1 Phase 1 · 提取选路（识别特征 → 直取对应原子能力）

**先侦察，再决策。不要一上来就跑某个解包工具。**

```text
第 0 步（侦察，必做）：
  R1 file + magic bytes  →  容器类型
  R2 熵分布              →  高熵区在哪里、是否整体加密
  R3 头部/分区           →  各段起止、嵌套层级
  ↓
按识别结果分支（命中即取对应原子能力）：
├─ 熵 > 7.9 且无任何已知魔数、无文件系统候选        → E9 判加密
│    └ 先 R2 圈出高熵区边界 → 在内核/引导区找解密函数或密钥 → 解出后回到本条开头重跑
│    不要硬审乱码，也不要把「解不开」当成「审计完成」
├─ SquashFS 魔数（hsqs / sqsh）                     → E2 unsquashfs / moria -e
│    └ 解出为空 或 报 unsupported compression → 换 sasquatch 版 unsquashfs，或 moria -e（多压缩后端）
├─ UBI# 头 / UBIFS 节点                             → E3 ubireader → 失败 → moria -e
├─ JFFS2 魔数（0x1985，注意大小端）                  → E4 jefferson → 失败 → moria -e
├─ ext2/3/4 · F2FS · EROFS · cramfs · romfs         → E5 对应工具（debugfs / dump.f2fs / fsck.erofs / cramfsck）
├─ cpio / tar / gzip / xz / zstd 流                 → E1 unblob 递归（当前层是中间层，继续下钻）
├─ uImage / FIT / ARM64 Image / zImage              → E6 切内核 → E7 取 DTB+bootargs → E8 恢复符号
├─ 升级包/私有容器（非标头、厂商签名）              → R3 解头部 → 取载荷 → 回到本条开头
└─ 完全无法识别                                      → E1 unblob（carve + 78+ 格式）
     └ 仍拿不到文件系统 → 记 manifest + warning，转人工 hexdump 分析；不要静默用「兜底工具」糊过去
```

**失败信号（触发换路，而不是重试同一个命令）**——两级门，看「有没有拿到可用文件系统」，不看退出码：

| 级 | 判据（任一命中即视为该能力失败） |
|---|---|
| **L1 进程级** | ① 命令不存在（`command -v` 失败）② 退出码 ≠ 0 **且** 输出目录为空/未创建 ③ 超时被杀 / OOM（>15 min 无新产物） |
| **L2 产物级（决定性）** | ④ manifest 空或 0 个 chunk ⑤ **未产出任何可识别文件系统**（只有 carve 出的裸文件/压缩流）⑥ 识别到文件系统 chunk 但标记 `unhandled`/`error`（典型：缺 `sasquatch` → SquashFS 静默为空） |

**「可用文件系统」的客观定义**（三条同时满足，缺一即视为未成功、按 §3.1 换路）：

```text
rootfs_ok := 存在目录 D，满足
  (a) D 下有 {bin|usr|etc|lib} 中至少 2 个；
  (b) D 下 ELF 文件数 ≥ 1，或 shell 脚本数 ≥ 1；
  (c) D 下有 bin/sh、bin/busybox、etc/init.d/ 三者之一。
```

**反向判据（不要误换路）**：退出码 0 且拿到合规 rootfs，只是个别未知块/边角文件没解 → 记 `warning`，**不换路**；把未解块路径记进 manifest 供后续手撸。

**降级不丢弃上一级产物**：carve 出的块、内核、DTB 全部保留并合并进 `01-extract/`。

**每次决策都要留痕**（`01-manifest.json` 的 `extraction` 段），记录**为什么走这条路**，而不是只有「用了哪个工具」：

```json
"extraction": {"attempts": [
  {"capability": "E1", "impl": "unblob",  "verdict": "fail", "reason": "L2-⑥ squashfs chunk unhandled (sasquatch missing)", "out": "01-extract.unblob"},
  {"capability": "E2", "impl": "binwalk", "verdict": "fail", "reason": "L2-⑤ carved blobs only, no filesystem",        "out": "01-extract.binwalk"},
  {"capability": "E2", "impl": "moria",   "verdict": "ok",   "reason": "squashfs 2547 files; bin/busybox + etc/init.d present", "out": "01-extract"}
]}
```

**提取完立即衔接内容级扫描**：`C1` 凭据 → `C2` SBOM → `C3` CVE（只记 `cve-hit`）→ `C4` 启动姿态，然后再进 `F1–F6` 文件系统侦察。顺序不能颠倒：**先知道自己拿到了什么，再决定审什么。**

### 3.2 Phase 4 · 仿真选路（反馈驱动，判据在节点上）

先问一个更高层的问题：**你到底要证明什么？** 判据不是「哪个工具更强」，而是「要把哪一条 HYPOTHESIS 升成 CONFIRMED」。

```text
Q1 要验证的是哪一类结论？
│
├─ (A) 整机 / 服务可达性（路由可达？认证状态？）
│   Q2 内核能否提取（E6）且 rootfs 完整（rootfs_ok）？
│    ├─ 能 → 调用 D1：qemu-system-<arch> 直接启动（带上 E7 的 bootargs）
│    │    └─ 启动失败 → 调用 D2 读串口/dmesg，按失败原因分支（不要直接换工具重跑）：
│    │        ├─ "no init found" / VFS mount fail → 文件系统格式或 root= 错 → D3 修 bootargs / 换 init
│    │        ├─ 找不到 root device（mtdblock?）  → 分区号/mtd 布局 → D3 改 mtdparts / 手工建节点
│    │        ├─ CPU/SoC 不匹配 / 无机器描述      → 指定 -M 或补 DTB（回 E7）
│    │        ├─ 卡在启动脚本等硬件（watchdog/NVRAM）→ D3 改 init 或 stub 掉该步骤
│    │        └─ 内核与自带驱动不兼容（老 mtd/flash 驱动）→ 换厂商同版内核；仍不行 → 降级到 (B)
│    │    └─ 启动成功 → 调用 D4 探测真实服务/路由，再回到 Phase 3 补证据
│    └─ 不能（内核加密/缺失/rootfs 不全） → 直接走 (B)
│
├─ (B) sink 参数真值（命令注入 / 路径穿越 / 逻辑缺陷 / 认证绕过）
│   Q3 二进制能否加载并跑到 sink？
│    ├─ 能 → 调用 D5 Qiling + D6 打桩缺失依赖 + D7 hook sink 看实参真值
│    ├─ Qiling 因私有 syscall / 加壳失败 → D8 strace/qemu-user 追调用序列 + N2/N3 手工构造请求
│    └─ 完全无法执行 → 回退静态闭环（Phase 3），结论保持 HYPOTHESIS，**不得声称已验证**
│
├─ (C) 内存破坏是否真实存在（溢出 / UAF / 格式化）
│   Q4 目标二进制能否在宿主原生跑？
│    ├─ 能（同 arch / 可 native build）        → D10 afl-fuzz -O（FRIDA）
│    ├─ 跨 arch 且为纯解析函数（无 syscall）    → D10 afl-fuzz -U（Unicorn，最快）
│    ├─ 跨 arch 且依赖 libc/文件/socket         → D10 afl-fuzz -Q（QEMU）
│    ├─ 是网络服务                              → 先 D5 写 harness（socket→文件）再喂 D10
│    └─ 有 magic / 校验和 / 长度比对            → D10 加 CmpLog（-c）或 laf-intel；必要时手工 patch 掉比较
│       然后 D11 逐个 triage 崩溃样本，判 PC 是否可控
│
└─ (D) 组件 CVE 是否可达
    这属于静态闭环（Phase 3 的「代码在 / 可达 / 未修复」三问），不需要仿真；
    只有当三问齐备、要复现时才回到 (A) 或 (B)。详见 SKILL.md Phase 4 §4.5。
```

**硬规则：**

1. **反馈优先于重试。** 启动失败先去读输出（dmesg/串口/strace），定位到具体原因再针对性修补；「换个仿真器重跑」是最后手段。
2. **不要为 fuzzing 而 fuzzing。** 只有 finding 类型是**内存破坏**、且静态链路已证可达时才开 AFL++。命令注入/认证绕过/路径穿越/逻辑缺陷用 D7 hook 看参数即可——这不是「跑崩了才算」，而是「参数到没到 sink」。对这类问题开 fuzzer 是纯浪费预算。
3. **每条 HYPOTHESIS 都要落明确结论。** 升成 CONFIRMED，或写清「为何当前条件下不可验证」并保持 HYPOTHESIS。禁止用「未验证」当作无限期搁置的借口（见 SKILL.md 铁律 5）。
4. **交叉验证要有，但不能替代主路径。** 想用整链工具做第二意见 → 见 §10.2，其输出按线索处理。

**三种 fuzz 模式速览**（同一套命令，模式决定插桩方式）：

| 模式 | 适用 | 相对速度 | 局限 |
|---|---|---|---|
| `-Q` QEMU | 跨架构黑盒，无需源码/插桩 | 中（~1–5k exec/s） | 需 AFL++ 的 qemu 支持该 arch |
| `-U` Unicorn | 纯函数，harness 把输入写进内存后调用 | 最快 | 不能有 syscall / 文件依赖 |
| `-O` FRIDA | 目标能在宿主原生跑或已 native build | 快 | 需 ptrace / root |

### 3.3 Phase 3 · Layer 1 引擎选路（脚本 / web 目标的结构级二次过滤）

Layer 1 的主引擎永远是**正则初筛**（`sink_scan.py` + `sink-rules.json` 的 `patterns`）：快、全量、不限语言。但对**脚本 / web 目标**，正则有一个结构性缺陷——**分不清「代码」与「注释 / 字符串」**：

```bash
# 下面三行正则都会命中 system(
// system($x);              # 注释里的假调用
echo "system(id)";          # 字符串里的假调用
system($cmd);               # 真调用
```

**判据（命中即取，逐级回退，回退必须记录）**：

```
文件被正则命中，且该规则带 structural？
├─ 否 → 保持正则结果（正常路径，无需记录）
└─ 是 → 文件语言可判？（先看 LANG_BY_EXT 扩展名，再看 shebang / <?php）
   ├─ 否 → 回退正则，记 fallback = lang-undetected
   └─ 是 → 该语言有 structural 变体？
      ├─ 否 → 回退正则，记 fallback = lang-unsupported
      └─ 是 → 引擎二进制可用？
         ├─ 否 → 回退正则，记 fallback = engine-missing
         └─ 是 → 跑结构匹配（同一变体内多模式取 OR）
            ├─ 结构确认 → 保留命中，标 engine = <引擎>
            ├─ 结构否定 → 丢弃该命中（判为注释 / 字符串误报），计 filtered
            └─ 解析失败 / 超时 → 回退正则，记 fallback = engine-error
```

**铁律**：

1. **只作二次过滤，不作候选生成器。** 结构引擎只在**正则已命中**的文件上运行，不负责发现新候选。这样成本被正则约束住，也不改变 Layer 1 的召回语义。
2. **对剥离符号的 ELF 不适用。** ast-grep / semgrep 是**源码级**工具。**不要**把反编译伪代码喂给它们——IDA 伪代码不是合法 C（`sub_XXXX`、`__int64`、`goto LABEL_xx`、非标转型），C 解析器会产出垃圾 AST，导致假阳性与静默漏检。这是实验级思路，不进主路径。
3. **语言判不出就回退并记录。** 固件脚本常无扩展名、shebang 指向 busybox ash、厂商方言未必能被 tree-sitter 解析。任何回退都写进 `engine_status.fallbacks`，**不得静默**。
4. **引擎缺席只影响噪声比，不影响结论强度。** 回退正则与结构过滤后的命中同属「形态存在」，都必须经 Layer 3 确认。

> `ast-grep`（`sg`）与 `semgrep` 在 Layer 1「过滤注释 / 字符串」这件事上**职责重叠**——**选一个即可**，不要两个都塞进 Layer 1（会引入三套规则 DSL）。`semgrep` 的独立价值在 Layer 2/3 的**污点追踪**（见 §5.2）。

---

## 4. 提取与解包的实现细节

### 4.1 unblob（E1 首选实现）

```bash
uv pip install unblob                              # 或 apt install unblob；uvx unblob 可免安装直跑
unblob --show-external-dependencies             # 关键：先确认解包器齐全
unblob -e out/ --report report.json -d 10 -n 2 firmware.bin
unblob -P ./myplugins/ firmware.bin             # 自定义 handler 插件
```

- 支持 78+ 归档/压缩/文件系统格式，递归深度默认 10
- `--report` 产出 JSON：每个 chunk 的偏移、大小、类型、熵、属主、权限、时间戳
- **SquashFS 需要额外装 sasquatch**，否则整个 SquashFS 解不开（正是 §3.1 的 L2-⑥）：
  ```bash
  curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_$(dpkg --print-architecture).deb"
  sudo dpkg -i sasquatch_1.0.deb
  ```
- Ubuntu/Debian 依赖：`sudo apt install android-sdk-libsparse-utils e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover libhyperscan-dev zstd lz4`

### 4.2 binwalk v3（R1/R2 与 E1 备选实现）

```bash
cargo install binwalk       # 或 docker build；v3 与 v2 命令不完全兼容
binwalk firmware.bin                 # 仅识别
binwalk -e firmware.bin              # 提取
binwalk -Me firmware.bin             # 递归 + 熵分析
binwalk -E firmware.bin              # 只出熵图（R2）
```
v3 的签名库比 v2 小但更准，且是 Rust 实现（快）。**注意**：v2 的 Python 模块 API 在 v3 中不存在，历史脚本要改。

### 4.3 moria（E1–E5 通用实现，无需 root，进程内覆盖最全）

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
moria <file>                     # 可读 findings 树（偏移 + 类型 + 置信度）
moria -j <file>                  # JSON，供脚本/模型消费
moria -e <file> -C out/          # 解包到 <file>.extracted/
moria -c <file>                  # 只 carve 原始字节区间，不解析
moria -E <file>                  # 熵扫描，标记未识别/疑似加密区（R2）
moria --list <archive>           # 列举 tar/cpio/zip/cab/CE-ROM 成员，不解包
moria --broad <file>             # 额外加载 ~2.5k 通用文件类型签名
moria --unpack-executables       # 递归解包 cbf/msi 里的可执行体
moria --sigs DIR                 # 用外部签名（调规则时不必重编译）
```
moria 的相对优势：**进程内**支持 SquashFS / ext2-4 / F2FS / FAT / exFAT / NTFS / HFS+ / XFS / btrfs / JFFS2 / UBI-UBIFS / romfs / YAFFS2 / cramfs / EROFS，且对恶意输入做了边界检查与 `O_NOFOLLOW` 防护；检测 UPX 打包（含被抹头/改头的 stub）。注意 **moria 只做识别与解包，不扫密钥/凭据**（那是 mithril 的活）。

### 4.4 单文件系统实现（E2–E5 的针对性工具）

| 能力 | 实现 | 何时直接用它而不是 E1 |
|---|---|---|
| E2 SquashFS | `unsquashfs -d rootfs <img>` / `moria -e` | E1 缺 sasquatch 时补刀 |
| E3 UBI/UBIFS | `ubireader_extract_images`、`ubi_reader` | E1 解 UBI 失败时 |
| E4 JFFS2 | `jefferson` | 老路由器常见的裸 JFFS2 分区 |
| E5 其他 FS | `debugfs -R rdump`、`dump.f2fs`、`fsck.erofs --extract`、`cramfsck -x` | 单文件系统镜像 |

### 4.5 重打包（做验证时才需要）

`firmware-mod-kit` —— 解包 + 重打包，用于改固件后回灌设备验证；不做验证就别引入这个复杂度。

---

## 5. 内容级分析的实现细节

### 5.1 mithril（C1–C5 的实现，与 moria 配套）

```bash
mithril --fetch-db                # 仅首次：下载本地 CVE 镜像（联网，SHA-256 校验）
mithril --update-db               # 自行从上游重建镜像（联网，可控性更强）
mithril -j <dir>                  # 全部 pass，JSON
mithril --secrets <dir>           # 凭据/密钥/JWT/高熵 KEY= 值；/etc/shadow 与 htpasswd 带弱算法与空口令标记
mithril --sbom -C out/ <dir>      # CycloneDX + SPDX
mithril --cve <dir>               # 组件 CVE（本地镜像，离线，带 CISA KEV 与 EPSS 标注）
mithril --cve --kernel-cves-all <dir>      # 列出内核版本对应的全部 kernel.org CVE
mithril --licenses --license-paths <dir>   # 许可证 + 文件位置
mithril --boot <dir>              # U-Boot env / device tree / FIT-AVB / UEFI Secure Boot 姿态
mithril --boot bios.bin           # 裸 BIOS 的 UEFI Secure Boot 姿态
mithril --keys <dir>              # 公钥弱点：默认/泄露密钥、ROCA、弱 RSA、可因式分解
mithril --rules my.json <dir>     # 用户自定义规则
```

**重要认知**：
- `--secrets` 走确定性阶梯：`pattern`（形状）→ `structural`（可解析的 JWT/PEM）→ `validated`（校验和重算，如 GitHub token）。它只断言「格式良好」，从不断言「凭据有效」；**空结果是真结果，不是工具故障**。
- `--cve` 默认视图只展示「可作为立足点」的组件 CVE（KEV 上的 / Critical / CVSS≥7.0 且 EPSS 有热度、低攻击复杂度、有实际影响），会主动过滤 Medium、本地 DoS、高复杂度密码学类。想看全量用 `--component-cves-all`。

  **版本命中 ≠ 可利用，甚至 ≠ 漏洞存在。** `--cve` 只做版本区间比对，**不问代码是否存在、是否可达**。五道缺口必须逐一排除：代码不存在（编译期裁剪）、已 backport（改过补丁但没改版本号）、编译选项未开、运行时配置未达、无可达输入路径。因此：
  - 所有 `--cve` 结果状态一律先标 `cve-hit`，措辞「疑似…尚未验证可达性」
  - 写入 `20-findings-candidates.jsonl` 时 `track="component"`、`confidence="candidate"`
  - **不计入漏洞总数、不打 CVSS、不映射 P0-P3**，报告里单列「组件风险（未验证）」区块
  - 升级为漏洞必须补齐三项检查：**代码在** + **可达** + **未修复**。详见 `references/reporting.md` 第 ⑥ 区块与 SKILL.md 铁律 7
- 全程离线、无网络调用（除 `--fetch-db` / `--update-db`），可气隙运行。

### 5.2 结构级脚本扫描（C6 的实现：ast-grep / semgrep）

**定位**：Layer 1 的二次过滤（ast-grep），以及 Layer 2/3 对**源码类目标**的污点辅助（semgrep taint）。

```bash
# --- Layer 1 二次过滤（由 sink-rules.json 的 structural 字段驱动，无需手工切引擎） ---
python sink_scan.py 01-extract --ast-grep-bin ast-grep --json 10-layer1-sinks.json
python sink_scan.py 01-extract --no-structural       # 强制纯正则，用作对照基线

# 单独看某个规则的结构命中（调试规则时用）
ast-grep run --pattern 'system($$$ARGS)' --lang php --json=stream webs/x.php
ast-grep run --pattern 'eval $$$ARGS'    --lang bash --json=stream etc/rc.d/x.sh
# 命令名 ast-grep 或 sg 均可

# --- Layer 2/3：源码类目标的污点追踪（taint mode，需 YAML 规则） ---
semgrep --config taint-rule.yaml --json rootfs/webs
semgrep -e 'system(...)' --lang php --json webs/x.php        # 单模式检索
```

**规则写法**（只给 P0/P1 的 script/web 规则加，P2/P3 保留正则）：

```json
{
  "id": "P0-W-001",
  "patterns": ["\\bsystem\\s*\\("],
  "structural": [
    {"engine": "ast-grep", "language": "php",
     "pattern": ["system($$$ARGS)", "exec($$$ARGS)", "shell_exec($$$ARGS)"]}
  ]
}
```

- `patterns` 是**回退保留项**：引擎缺失或解析失败时仍能工作，不丢能力。
- `pattern` 可为字符串或字符串数组（数组内 **OR** 语义：任一确认即视为确认）。

**约束与坑**：

- semgrep 扫大目录时**文件定位阶段会显著变慢**（上万文件级达分钟级）。**只对 T1/T2 的脚本与 web 目录运行**，不要全量扫 rootfs；必要时用 `--max-target-bytes` 限单文件大小。
- 两个引擎的规则语法**互不兼容**：ast-grep 是「模式即代码」，semgrep 是 YAML + 专用模式语法。**不要试图共用一套规则文件**。
- 引擎可执行文件通过 `--ast-grep-bin` / `--semgrep-bin` 指定；`engine_status.engines` 会记录实际解析到的路径。
- 新增规则必须先用 `--only-rule <id>` 跑通再进流水线。

---

## 6. 逆向与静态分析的实现细节

| 能力 | 实现 | 命令要点 |
|---|---|---|
| B1 架构识别 | binutils / `file` | `readelf -h` 看 `Machine`/`Class`/`Data`；ARM 看 `Tag_ABI_VFP_args`；MIPS 看 `e_flags` 的 ABI（o32/n32/n64） |
| B2 符号与导入 | binutils | `readelf -d/-s/-l`、`nm -D --undefined-only`、`strings -a -t x` |
| B3 sink 定位 | radare2 / rizin / `fw_triage.py` | `r2 -A -q -c 'aaa; axt @ sym.imp.system' bin`；`afl` 列函数；`pdf` 反汇编；`/x` 搜字节；`izz` 列字符串 |
| B4 反编译追链 | Ghidra 无头 | `analyzeHeadless <projdir> <name> -import bin -postScript X.java -processor ARM:LE:32:v7` |
| B6 数据流 | angr | 符号执行找可达路径（`find=`/`avoid=`） |
| B9 库识别 | FLIRT / Ghidra FID | 剥离符号时的救命手段 |
| B8 二进制比对 | BinDiff / Diaphora / Ghidriff | 官方补丁 diff 定位漏洞 |

其它可替换实现：Binary Ninja / IDA Pro（商业，反编译质量高）、Cutter（radare2 GUI）、retdec / rev.ng（开源反编译器）、Frida / ret-sync（动态插桩）。

**符号剥离时的定位法**：字符串锚点（`strings -t x`）→ 在反汇编中找引用该地址的指令 → 从引用点回溯调用者 → 结合 xref 建链。

### 6.1 二进制逆向 MCP（B4 的主力实现）

固件逆向最耗时的是「字符串锚点 → 引用点 → 回溯调用者」这类三跳追链，手工做几十上百次。MCP 把这层变成模型可直接调用的能力。

| MCP | 仓库 | 前置 | 定位 |
|---|---|---|---|
| **`ida-mcp`** | `HexRaysSA/ida-mcp`（官方 Hex-Rays） | IDA **9.4+**（含 idalib）+ Python 3.11+ + `uv` | 首选。反编译 + xref + 在 IDA 进程内跑 IDAPython |
| **`pyghidra-mcp`** | 社区 | Ghidra + JDK | 免费路线，无头 Ghidra 反编译查询 |

**`ida-mcp` 的六个工具**（能力集中在 `execute_python`）：

```
open_database(path, set_current=True)          # 打开/接管样本（GUI 里开着的也能接管）
execute_python(code, instance_id=None, timeout=360)   # ★ 在 IDA 进程内跑 Python
reference(query)                               # ida-domain API 参考查询
list_databases() / save_database() / close_database()
```

`execute_python` 里用 **ida-domain** API（IDA 9.1+；底层 `ida_nexus`）。固件场景常用：

```python
f = db.functions.get_at(0x2a30)                  # 按地址取函数
db.functions.get_pseudocode(f).to_text()         # 伪代码（真语义，非字符串猜谜）
for x in db.xrefs.to_ea(0x1c40):                 # 谁引用了该字符串地址
    print(hex(x.from_ea), x.type.name)           # → 定位到调用点
db.xrefs.calls_to_ea(sink_ea)                    # 只取 call 类 xref
db.functions.get_disassembly(f)                  # 反汇编
db.bytes.find_text_between('ping')               # 字节/字符串搜索
db.functions.get_flowchart(f)                    # CFG，block.get_successors()
db.strings                                       # 全部字符串（含 .address）
db.signature_files.apply(sig, probe_only=True)   # FLIRT 库函数识别（剥离符号时救命）
db.segments / db.names / db.entries / db.imports
```

批量建库（不经 MCP，直接跑）：

```bash
uvx ida-nexus python firmware.bin -c 'db.functions.get_all()'
uvx ida-mcp stdio                          # stdio MCP
uvx ida-mcp http --host 127.0.0.1 --port 8737   # Streamable HTTP
uvx ida-mcp dashboard --open               # 会话/成本面板
```

> `stdio` 子命令另有**可选**参数 `--agent <名称>`（官方说明 "Agent name to record in the MCP session trace"）——只写进会话跟踪元数据，不影响鉴权与功能，可省略。

MCP 配置（写入**你所用 Agent 的 MCP 配置文件**，形如 `~/.<agent>/mcp.json`；改后在连接器管理页点「信任」才生效）：

```json
{"mcpServers": {"ida": {"command": "uvx",
  "args": ["--exclude-newer=1s", "ida-mcp", "stdio"]}}}
```

**坑（必读）**：
- **授权**：需商业 IDA 9.4+，**没有就退回 Ghidra/radare2**，不要在这上面卡住流程（这就是 §11 的意义）
- **写库**：`execute_python` 默认 `flush_database=True`，会立即写 `.id0/.id1` 缓冲区。**对固件二进制先在副本上操作**，或开 `save_on_close=False`
- **超时**：超时只是「请求中断」，阻塞型调用（`time.sleep()`）可能仍在跑
- **不重试**：失败**不自动重试**（可能已改动数据库）；重新执行前先确认库状态
- **伪代码不是证据**：反编译器会猜错函数边界、变量类型、调用约定。伪代码用于理解控制流，**finding 的原文证据必须是反汇编/字节**
- 多条 IDA MCP 共存会互相干扰（官方建议关掉其它 IDA MCP）

### 6.2 三条路径的取舍（任何环境都必须能跑）

```bash
# 路径 A：有 ida-mcp 时（真语义，最省人力）
# 见 §6.1

# 路径 B：无 MCP 时的替代链
# 1) 反汇编 / 交叉引用（radare2，可脚本化，最通用）
r2 -A -q -c 'aaa; axt @ sym.imp.strcpy' usr/sbin/httpd
r2 -A -q -c 'afl~cgi; s main; pdf' usr/sbin/httpd

# 2) 反编译（Ghidra 无头，批量，免费路线的语义级）
analyzeHeadless /tmp/ghidra_proj FW -import usr/sbin/httpd -postScript Decompile.java

# 3) 永远可用的交叉验证：binutils（输出本机过滤用 rg）
objdump -d -M intel usr/sbin/httpd | rg -A20 '<system@plt>'

# 4) 符号剥离时的兜底：字符串锚点 → 引用点 → 回溯调用者
strings -a -t x usr/sbin/httpd | rg -i 'ping|ifconfig|kill'
```

取舍顺序：**MCP 反编译（真语义）> Ghidra 无头（批量语义）> radare2 手工追链（可行但慢）> objdump+strings（兜底）**。无论走哪条，**证据等级不打折**——区别只在成本，不在结论强度。

---

## 7. 模拟与模糊的实现细节

### 7.1 Qiling（D5–D7 的首选实现，单二进制）

```bash
uv tool install qiling && qiling setup      # 免污染环境；或用 uvx qiling
qltool run -f ./usr/bin/httpd --rootfs ./rootfs
qltool run -f ./b --rootfs ./rootfs --gdb 127.0.0.1:9999
qltool code --os linux --arch arm --format hex -f shellcode.hex
qltool run -f ./b --rootfs ./rootfs --coverage-format drcov --coverage-file b.cov
```

能力：Windows/macOS/Linux/Android/BSD/UEFI/DOS/MBR × 8086/x86/x64/ARM/ARM64/MIPS/RISC-V/PPC，支持 PE/Mach-O/ELF/COM/MBR，支持 `.sys`/`.ko`/`.kext`（Demigod）。基于 Unicorn，但补上了可执行格式加载、动态链接、syscall 与 IO 处理，因此**不需要目标原生 OS**。可以热补丁运行中的代码、带反向调试的调试器、任意层级 hook。

### 7.2 整机模拟（D1 的实现族）

| 实现 | 定位 |
|---|---|
| `qemu-system-*`（手工） | **首选**：直接可控，启动失败时错误信息最原始，便于 D2 诊断 |
| FAT（`fat emulate`） | QEMU 编排较完整，可作为「手工起不来时的对照」 |
| Firmadyne / FirmAE | 经典自动化仿真（FirmAE 成功率更高，会自动修 NVRAM/网络） |
| QEMU user（`qemu-arm -L rootfs ./httpd`） | 单二进制，无需内核（D5 的轻量实现） |
| Renode | 裸机/RTOS 仿真（Zephyr、FreeRTOS） |
| HALucinator | 通过 HAL 库替换做嵌入式固件再宿主化 |
| Unicorn Engine | 纯 CPU 仿真（无 OS 概念），适合做函数级 harness |
| Avatar2 | 动态分析编排（真实硬件 + 模拟器混合） |
| PANDA / S2E / SymQEMU | 记录回放、选择性符号执行 |
| FirmWire | 基带固件仿真 |

> 整机模拟起不来的细节排查清单（按出现频率排序）见 `references/emulation-fuzzing.md` §2。

### 7.3 AFL++（D10 的实现）

```bash
# 有源码
CC=afl-cc ./configure --disable-shared && make
afl-fuzz -i seeds/ -o out/ -- ./target @@
AFL_LLVM_CMPLOG=1 afl-clang-fast target.c -o target     # 提升比较类路径
# 无源码三模式
afl-fuzz -Q ...     # QEMU（覆盖广）
afl-fuzz -U ...     # Unicorn（快）
afl-fuzz -O ...     # FRIDA（目标可在宿主跑）
# 辅助
afl-cmin -i in/ -o out/ -- ./target @@      # 语料最小化
afl-tmin -i crash -o min -- ./target @@     # 崩溃用例最小化
afl-showmap -o map -- ./target @@           # 覆盖率确认
```
配套：`cov-analysis`（源码覆盖率报告）、`fuzz-reachability`（静态判断 harness 可达哪些函数，区分真实覆盖缺口与死代码）。协议模糊用 `boofuzz` / `Fuzzowski`；内核用 `syzkaller`；IoT 专用参考 FIRM-AFL、Snipuzz、Icicle。

---

## 8. 网络协议与利用的实现细节

| 目标 | 实现 |
|---|---|
| MQTT | `mosquitto_pub/sub`、MQTT Explorer、`IoXY`（拦截代理）、`MQTT-PWN`、Nmap mqtt 库 |
| CoAP | `libcoap` CLI、Scapy CoAP 插件、Copper4Cr |
| UPnP/SSDP/HNAP | `miranda`、`upnpwn`、自定义 Scapy 脚本 |
| 通用 IoT 利用 | `RouterSploit`、`HomePwn`、`expliot`、`PENIOT`、`PRET`（打印机）、`ISF`（工控） |
| BLE | `btproxy`、GATTacker、`crackle`、BTLEjack、BlueToolkit |
| Zigbee/802.15.4 | Killerbee、ZigDiggity、Zigator、ApiMote |
| SDR（433M/Sub-G） | HackRF + GNU Radio、RTL-SDR、`rpitx`（重放） |
| 云侧 | `CloudFox`、`S3Scanner`、`Pacu`、`ScoutSuite`、`Prowler` |
| 情报（N4） | Shodan、Censys、ZoomEye、BinaryEdge、FCC ID Database |

详细用法与仿真侧配合见 `references/resource-index.md`。

---

## 9. 硬件接口的实现细节（需物理接触）

| 接口 | 做法 |
|---|---|
| UART | 万用表找 GND/TX/RX（TX 空闲高电平、RX 高阻），波特率从 9600/38400/57600/115200 试；`screen /dev/ttyUSB0 115200`；根 shell 常见；U-Boot 阶段打断可改 `bootargs` 进单用户 |
| SPI NOR | CH341A + `flashrom -p ch341a_spi -r dump.bin`；先识别芯片丝印 |
| eMMC | 读卡器/SD 转接，或 ISP 引脚 |
| JTAG | `JTAGulator` 找引脚，`OpenOCD` 连接，GDB 直接读内存 |
| SWD | `pyOCD` / `OpenOCD` + ST-Link/J-Link，读 MCU 全部 flash |
| 故障注入 | ChipWhisperer（电压毛刺/时钟毛刺/Power Analysis） |
| 固件芯片型号未知 | 读丝印 → 查 datasheet → 确定读命令 |

此阶段产出的固件回到 Phase 1（§3.1）重新入链。

---

## 10. 规范、检查清单与整链工具的定位

### 10.1 写报告时引用的规范

- OWASP Firmware Security Testing Methodology（FWSTM）
- OWASP IoT Security Verification Standard（ISVS）
- OWASP IoT Top 10
- ETSI EN 303 645（消费级 IoT 基线）
- NISTIR 8259 / NIST SP 800-213
- Compiler Options Hardening Guide for C and C++（加固选项对照）
- `checksec.sh`（常规二进制加固检查；本 skill 的 `fw_triage.py` 用纯 Python 复刻其核心判据）

### 10.2 整链自动化工具：只做交叉验证基线

| 工具 | 它能做的 | 允许的用法 |
|---|---|---|
| FAT | 端到端编排（识别→提取→仿真→triage→taint） | 主路径跑完后做**第二意见**：它的 `sink-discovery`/`handler-table`/`taint` 输出与我们自己的 B3/B5/B6 对账，**差异即线索** |
| EMBA / FACT | 全自动扫描与多版本比对平台 | 交付需要平台化产物时用；**其 CVE 输出按 cve-hit 纪律处理** |
| Firmadyne / FirmAE | 自动化仿真 | 仅当手工 D1 起不来、想借它自动修 NVRAM/网络时**参考它的修补手法**，而不是把仿真托管给它 |
| `firmwalker` | 关键字扫描脚本 | 快速凭据扫描的**补充**，不能替代 C1 的确定性阶梯 |

**红线**：不允许把上述任一工具的输出直接当成 finding，也不允许因为它「跑通了」就认为审计完成。它的价值是**对照与查漏**，不是决策。

---

## 11. 能力不可用时的替代路径

> 列这张表的目的不是「有降级链所以不会卡死」，而是让你在**某个原子能力缺席**时，知道还有哪些实现能达到同一能力，以及**代价是什么**。

| 缺失的能力 | 替代实现 | 代价 / 是否影响结论强度 |
|---|---|---|
| `fd` | `find` | 语法变长、无并行；结论不变 |
| `rg` | `grep -r`（需加 `-I`，否则误扫二进制） | 噪声变大、变慢；结论不变 |
| `sg`（ast-grep） | `rg` + 多行正则（`-U`） | 跨行/格式差异下**可能漏检**；结构级二次过滤失效 → **注释/字符串误报回归**，结论不变（仍需 Layer 3 复核） |
| `semgrep`（taint） | 人工三跳追链（Layer 3 主力） | 自动化程度下降、更耗时；**结论强度不变** |
| E1 unblob | binwalk v3 → moria → 手工 `binwalk -E` + `dd` 按偏移切 | 格式覆盖下降，未知块丢失 |
| E2 sasquatch | `moria -e` / 从 `moria --list` 给的偏移手工 `unsquashfs` | 多一步；结论不变 |
| C1–C3 mithril | `firmwalker` + 自写 `rg` 规则 + 在线查 CVE（注意断网要求） | 失去 SBOM/KEV/EPSS 关联；CVE 结果的**可信度下降**（需更严格的三问复核） |
| D1 整机模拟 | QEMU user + `chroot`；或 Qiling 单二进制 | 需手工修补 rootfs；可达性结论**范围收窄**（只能证单二进制） |
| D5 Qiling | Unicorn 手写 harness / AFL++ QEMU 模式 | 工作量显著上升 |
| B3/B4 radare2 | Ghidra 无头 / `objdump` + `nm` + `strings` | 交叉引用需手工 |
| B4 `ida-mcp` | `pyghidra-mcp` → Ghidra 无头 → radare2 + binutils | MCP 断链即回到手工追链，效率降一个量级，**结论强度不变** |
| `pyghidra-mcp` | Ghidra 无头 `analyzeHeadless` | 需自己写 postScript 抽结果 |
| D10 AFL++ | `honggfuzz`、`libFuzzer`（有源码时） | 二进制模式支持弱 |
| N4 Shodan/Censys | 主动扫描（**需授权**） | 法律与噪声风险 |
