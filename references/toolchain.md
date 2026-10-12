# 工具链速查

本文件是 Phase 0-5 的工具使用手册，包含安装方式、命令、输出解读与**工具缺失时的替代/降级方案**。

## 0. 环境矩阵

| 环境 | 适用性 | 说明 |
|---|---|---|
| Linux 发行版（Kali / Ubuntu） | ★★★★★ | 全部工具原生可用 |
| Docker | ★★★★★ | 推荐。unblob / FAT 官方镜像自带全部解包器 |
| WSL2 | ★★★★ | 可用，注意 `/mnt/c` 上执行大文件解包会慢 |
| AttifyOS / EmbedOS / IoT Pentesting OS | ★★★★★ | 预装 Attify 全家桶 |
| Windows 原生 | ★★ | 只有本 skill 的三个 Python 脚本能原生跑；其余走 Docker |

Windows 下的 Docker 定式：

```bash
docker run --rm -v "$PWD:/data" -w /data ghcr.io/onekey-sec/unblob:latest /data/firmware.bin
docker run -ti -v "$PWD:/src" aflplusplus/aflplusplus
```

---

## 0.1 本机工具基线（优先使用，非 GNU 对应物）

分析过程中凡是「在**我自己的机器上**查文件 / 搜内容 / 跑 Python」，一律按下面的优先级，**不要默认用 `find` / `grep` / `pip`**：

| 场景 | 首选 | 替代（缺失时） | 要点 |
|---|---|---|---|
| **查找文件** | **`fd`**（Rust 重写 find） | `find` | 语法短、默认忽略 `.gitignore` 与隐藏项、并行遍历 |
| **过滤内容** | **`rg`**（ripgrep） | `grep` | 默认跳过二进制与 `.gitignore`、自动多线程、`-uu` 关忽略、`-t py` / `-g '*.sh'` 限类型 |
| **结构化代码搜索** | **`sg`**（ast-grep） | `rg` + 正则 | 按语法树匹配，跨语言、不受格式/换行影响；适合「找所有 `strcpy` 的第二参是否为常量」这类问题 |
| **Python 环境** | **`uv`** | `venv` + `pip` | `uv venv` / `uv pip install` / `uv tool install` / **`uvx` 免安装直跑** |

```bash
# 查找文件：fd 而不是 find
fd -e c -e h -e sh                       # 按扩展名
fd -t f -t f -H 'passwd|shadow'          # 含隐藏项
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

# Python：uv 而不是 pip / venv
uv venv .venv && source .venv/bin/activate
uv pip install unblob qiling
uv tool install binwalk                  # 装 CLI 工具
uvx ida-mcp stdio --agent=workbuddy      # 免安装直跑，不污染环境
uv run script.py                         # 用项目环境跑
```

> ⚠️ **重要边界**：这条规则只适用于**本机**（我的分析工作站）。一旦进入提取出的 rootfs，里面跑的 `grep`/`find`/`sh` 是**目标设备的 busybox 命令**——那部分不能换成 `rg`/`fd`，也不要用 `--include` 这类 GNU 扩展（busybox 不支持）。判断标准：这条命令是**我在自己机器上执行**，还是**在目标文件系统里执行**。

> 缺失时的处理：`fd`/`rg` 没装就用 `find`/`grep` 兜底，但**在报告与回复里显式注明降级**，不要静默替换——否则后人复现时命令对不上。

---

## 1. 提取与解包

### unblob（首选）

```bash
uv pip install unblob                              # 或 apt install unblob；uvx unblob 可免安装直跑
unblob --show-external-dependencies             # 关键：先确认解包器齐全
unblob -e out/ --report report.json -d 10 -n 2 firmware.bin
unblob -P ./myplugins/ firmware.bin             # 自定义 handler 插件
```

- 支持 78+ 归档/压缩/文件系统格式，递归深度默认 10
- `--report` 产出 JSON：每个 chunk 的偏移、大小、类型、熵、属主、权限、时间戳
- **SquashFS 需要额外装 sasquatch**，否则整个 SquashFS 解不开：
  ```bash
  curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_$(dpkg --print-architecture).deb"
  sudo dpkg -i sasquatch_1.0.deb
  ```
- Ubuntu/Debian 依赖：`sudo apt install android-sdk-libsparse-utils e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover libhyperscan-dev zstd lz4`

### binwalk v3（次选，Rust 重写）

```bash
cargo install binwalk       # 或 docker build；v3 与 v2 命令不完全兼容
binwalk firmware.bin                 # 仅识别
binwalk -e firmware.bin              # 提取
binwalk -Me firmware.bin             # 递归 + 熵分析
binwalk -E firmware.bin              # 只出熵图
```
v3 的签名库比 v2 小但更准，且是 Rust 实现（快）。**注意**：v2 的 Python 模块 API 在 v3 中不存在，历史脚本要改。

### moria（兜底，无需 root，进程内解包最全）

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
moria <file>                     # 可读 findings 树（偏移 + 类型 + 置信度）
moria -j <file>                  # JSON，供脚本/模型消费
moria -e <file> -C out/          # 解包到 <file>.extracted/
moria -c <file>                  # 只 carve 原始字节区间，不解析
moria -E <file>                  # 熵扫描，标记未识别/疑似加密区
moria --list <archive>           # 列举 tar/cpio/zip/cab/CE-ROM 成员，不解包
moria --broad <file>             # 额外加载 ~2.5k 通用文件类型签名
moria --unpack-executables       # 递归解包 cbf/msi 里的可执行体
moria --sigs DIR                 # 用外部签名（调规则时不必重编译）
```
moria 的相对优势：**进程内**支持 SquashFS / ext2-4 / F2FS / FAT / exFAT / NTFS / HFS+ / XFS / btrfs / JFFS2 / UBI-UBIFS / romfs / YAFFS2 / cramfs / EROFS，且对恶意输入做了边界检查与 `O_NOFOLLOW` 防护；检测 UPX 打包（含被抹头/改头的 stub）。注意 **moria 只做识别与解包，不扫密钥/凭据**（那是 mithril 的活）。

### 其他提取工具

| 工具 | 定位 | 何时用 |
|---|---|---|
| `unsquashfs`（squashfs-tools） | 单文件系统 | unblob 缺 sasquatch 时补刀 |
| `ubi_reader` / `ubireader_extract_images` | UBI/UBIFS | moria/unblob 解 UBI 失败时 |
| `jefferson` | JFFS2 | 老路由器 |
| `firmware-mod-kit` | 解包 + 重打包 | 需要改固件做验证时 |
| `EMBA` | 全自动固件分析（含仿真、CVE） | 想要端到端基线报告 |
| `FACT` | 固件分析比对平台（Web UI） | 多固件版本比对 |
| `firmwalker` | 关键字扫描脚本 | 快速凭据/URL 扫描 |
| `fwanalyzer` | 策略化固件检查 | 用规则文件做合规检查 |
| `ByteSweep` | 固件扫描器 | 补充 |
| `BinDiff` / `Diaphora` / `Ghidriff` | 二进制比对 | 官方补丁 diff 定位漏洞 |

---

## 2. 内容级分析

### mithril（静态内容扫描，与 moria 配套）

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

  ⚠️ **版本命中 ≠ 可利用，甚至 ≠ 漏洞存在。** `--cve` 只做版本区间比对，**不问代码是否存在、是否可达**。五道缺口必须逐一排除：代码不存在（编译期裁剪）、已 backport（改过补丁但没改版本号）、编译选项未开、运行时配置未达、无可达输入路径。因此：
  - 所有 `--cve` 结果状态一律先标 `cve-hit`，措辞「疑似…尚未验证可达性」
  - 写入 `20-findings-candidates.jsonl` 时 `track="component"`、`confidence="candidate"`
  - **不计入漏洞总数、不打 CVSS、不映射 P0-P3**，报告里单列「组件风险（未验证）」区块
  - 升级为漏洞必须补齐三项检查：**代码在**（固件内定位到受影响函数/签名）+ **可达**（外部输入到该函数的调用链）+ **未修复**（补丁特征不存在）。详见 `references/reporting.md` 第 ⑥ 区块与铁律 7
- 全程离线、无网络调用（除 `--fetch-db` / `--update-db`），可气隙运行。

### FAT（Firmware Analysis Toolkit）

```bash
fat doctor                                     # 环境自检
fat ./firmware.bin                             # = fat identify --file
fat inspect update --file fw.bin --rootfs ./rootfs --reference ./older.bin   # 版本比对
fat inspect mcu --file fw.bin --details        # 裸 MCU 镜像：向量表、内存映射、外设
fat tree --rootfs ./rootfs --profile inventory --summary --json
fat search --rootfs ./rootfs --profile credentials -I --context 2
fat startup-map --rootfs ./rootfs --profile cloud-tls
fat crypto-census --rootfs ./rootfs            # 密码学用法普查
fat trust-map --rootfs ./rootfs                # 信任边界与可信二进制
fat r2-triage --file ./usr/sbin/httpd --json   # 二进制分诊（导入/导出/handler 表/sink）
fat sink-discovery --file ./usr/sbin/httpd --json > sinks.json
fat handler-table --file ./usr/sbin/httpd --json > handlers.json
fat taint --file ./www/cgi-bin/diag.cgi --summary
fat taint --lang shell --rootfs ./rootfs --summary
fat taint --file ./usr/sbin/httpd --sink-candidates sinks.json --json > taint.json
fat instrument-hooks --from-sinks sinks.json --output hooks.yaml
fat emulate --project .fat-projects/<proj> --instrument hooks.yaml
fat invariant query --fixture <dir> --rule 'Every privileged override method must call enforcePermission()'
```

支持分析对象：未知 blob/目录、固件镜像（头/更新包/分区/bootloader/差异）、解包后的 Linux 文件系统、ELF（含 stripped 的 sink 发现与 handler 表）、裸机与 MCU 镜像、Edge AI 产物（MAGIK/JZDL、TFLite、ONNX、Qualcomm DLC）、Android APK、源码仓库。
**安全提醒**：`fat emulate` 执行不可信厂商代码，可能出网。务必隔离。

---

## 3. 逆向与静态分析

| 工具 | 命令要点 |
|---|---|
| radare2 / rizin | `r2 -A -q -c 'aaa; axt @ sym.imp.system' bin`；`afl` 列函数；`pdf` 反汇编函数；`/x` 搜字节；`izz` 列字符串 |
| Ghidra（无头） | `analyzeHeadless <projdir> <name> -import bin -postScript X.java -processor ARM:LE:32:v7` |
| binutils | `readelf -h/-d/-s/-l`、`objdump -d -M intel`、`nm -D --undefined-only`、`strings -a -t x` |
| angr | 符号执行找可达路径（`find=`/`avoid=`） |
| Frida / ret-sync | 动态插桩、与 IDA/Ghidra 同步 |
| Binary Ninja / IDA Pro | 商业，反编译质量高 |
| Cutter | radare2 的 GUI |
| retdec / rev.ng | 开源反编译器 |
| `file` / `libmagic` | 快速类型识别 |

### 3.1 二进制逆向 MCP（模型直接操作反编译器）

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
uvx ida-mcp stdio --agent=workbuddy        # stdio MCP
uvx ida-mcp http --host 127.0.0.1 --port 8737   # Streamable HTTP
uvx ida-mcp dashboard --open               # 会话/成本面板
```

MCP 配置（写入 `~/.workbuddy/mcp.json`，改后在连接器管理页点「信任」才生效）：

```json
{"mcpServers": {"ida": {"command": "uvx",
  "args": ["--exclude-newer=1s", "ida-mcp", "stdio", "--agent=workbuddy"]}}}
```

**坑（必读）**：
- **授权**：需商业 IDA 9.4+，**没有就退回 Ghidra/radare2**，不要在这上面卡住流程
- **写库**：`execute_python` 默认 `flush_database=True`，会立即写 `.id0/.id1` 缓冲区。**对固件二进制先在副本上操作**，或开 `save_on_close=False`
- **超时**：超时只是「请求中断」，阻塞型调用（`time.sleep()`）可能仍在跑
- **不重试**：失败**不自动重试**（可能已改动数据库）；重新执行前先确认库状态
- **伪代码不是证据**：反编译器会猜错函数边界、变量类型、调用约定。伪代码用于理解控制流，**finding 的原文证据必须是反汇编/字节**
- 多条 IDA MCP 共存会互相干扰（官方建议关掉其它 IDA MCP）

**架构识别口诀**：`readelf -h` 看 `Machine` 与 `Class`；MIPS 大端小端看 `Data` 字节序；ARM 看是否有 `Tag_ABI_VFP_args`（硬浮点）；`e_flags` 里的 MIPS ABI（o32/n32/n64）。

**符号剥离时的定位法**：字符串锚点（`strings -t x`）→ 在反汇编中找引用该地址的指令 → 从引用点回溯调用者 → 结合 `cross-reference` 建链。

---

## 4. 模拟与模糊

### Qiling（推荐用于单二进制）

```bash
uv tool install qiling && qiling setup      # 免污染环境；或用 uvx qiling
qltool run -f ./usr/bin/httpd --rootfs ./rootfs
qltool run -f ./b --rootfs ./rootfs --gdb 127.0.0.1:9999
qltool code --os linux --arch arm --format hex -f shellcode.hex
qltool run -f ./b --rootfs ./rootfs --coverage-format drcov --coverage-file b.cov
```

能力：Windows/macOS/Linux/Android/BSD/UEFI/DOS/MBR × 8086/x86/x64/ARM/ARM64/MIPS/RISC-V/PPC，支持 PE/Mach-O/ELF/COM/MBR，支持 `.sys`/`.ko`/`.kext`（Demigod）。基于 Unicorn，但补上了可执行格式加载、动态链接、syscall 与 IO 处理，因此**不需要目标原生 OS**。可以热补丁运行中的代码、带反向调试的调试器、任意层级 hook。

### 整机模拟

| 工具 | 定位 |
|---|---|
| FAT（`fat emulate`） | QEMU 编排最完整，适合首次尝试 |
| Firmadyne / FirmAE | 经典自动化仿真（FirmAE 成功率更高） |
| QEMU（system / user） | `qemu-arm -L rootfs ./httpd`；`chroot rootfs qemu-mipsel-static ./bin/sh` |
| Renode | 裸机/RTOS 仿真（Zephyr、FreeRTOS） |
| HALucinator | 通过 HAL 库替换做嵌入式固件再宿主化 |
| Unicorn Engine | 纯 CPU 仿真（无 OS 概念），适合做函数级 harness |
| Avatar2 | 动态分析编排（真实硬件 + 模拟器混合） |
| PANDA / S2E / SymQEMU | 记录回放、选择性符号执行 |
| FirmWire | 基带固件仿真 |

### AFL++

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

## 5. 网络协议与利用

| 目标 | 工具 |
|---|---|
| MQTT | `mosquitto_pub/sub`、MQTT Explorer、`IoXY`（拦截代理）、`MQTT-PWN`、Nmap mqtt 库 |
| CoAP | `libcoap` CLI、Scapy CoAP 插件、Copper4Cr |
| UPnP/SSDP/HNAP | `miranda`、`upnpwn`、自定义 Scapy 脚本 |
| 通用 IoT 利用 | `RouterSploit`、`HomePwn`、`expliot`、`PENIOT`、`PRET`（打印机）、`ISF`（工控） |
| BLE | `Bluetooth` 栈：`btproxy`、GATTacker、`crackle`、BTLEjack、BlueToolkit |
| Zigbee/802.15.4 | Killerbee、ZigDiggity、Zigator、ApiMote |
| SDR（433M/Sub-G） | HackRF + GNU Radio、RTL-SDR、`rpitx`（重放） |
| 云侧 | `CloudFox`、`S3Scanner`、`Pacu`、`ScoutSuite`、`Prowler` |
| 情报 | Shodan、Censys、ZoomEye、BinaryEdge、FCC ID Database |

---

## 6. 硬件接口（需物理接触时）

| 接口 | 做法 |
|---|---|
| UART | 万用表找 GND/TX/RX（TX 空闲高电平、RX 高阻），波特率从 9600/38400/57600/115200 试；`screen /dev/ttyUSB0 115200`；根 shell 常见；U-Boot 阶段打断可改 `bootargs` 进单用户 |
| SPI NOR | CH341A + `flashrom -p ch341a_spi -r dump.bin`；先识别芯片丝印 |
| eMMC | 读卡器/SD 转接，或 ISP 引脚 |
| JTAG | `JTAGulator` 找引脚，`OpenOCD` 连接，GDB 直接读内存 |
| SWD | `pyOCD` / `OpenOCD` + ST-Link/J-Link，读 MCU 全部 flash |
| 故障注入 | ChipWhisperer（电压毛刺/时钟毛刺/Power Analysis） |
| 固件芯片型号未知 | 读丝印 → 查 datasheet → 确定读命令 |

---

## 7. 规范与检查清单（写报告时引用）

- OWASP Firmware Security Testing Methodology（FWSTM）
- OWASP IoT Security Verification Standard（ISVS）
- OWASP IoT Top 10
- ETSI EN 303 645（消费级 IoT 基线）
- NISTIR 8259 / NIST SP 800-213
- Compiler Options Hardening Guide for C and C++（加固选项对照）
- `checksec.sh`（常规二进制加固检查；本 skill 的 `fw_triage.py` 用纯 Python 复刻其核心判据）

---

## 8. 工具缺失降级矩阵

| 缺失工具 | 降级方案 | 代价 |
|---|---|---|
| `fd` | `find`（注意 `-exec … +` 与 `.gitignore` 行为差异） | 语法变长，无并行 |
| `rg` | `grep -r`（会误扫二进制与 `.gitignore` 内容，需加 `-I`） | 噪声变大，速度下降 |
| `sg`（ast-grep） | `rg` + 多行正则（`-U`） | 跨行/格式差异下漏检 |
| unblob | binwalk v3 → moria → 手工 `binwalk -E` + `dd` 按偏移切 | 格式覆盖下降，未知块丢失 |
| sasquatch | `moria -e` / `unsquashfs` 从 `moria --list` 给出的偏移手工解 | 需要两步 |
| mithril | `firmwalker` + 自写 grep 规则 + 在线查 CVE（注意断网要求） | 失去 SBOM/KEV/EPSS 关联 |
| FAT 仿真 | QEMU user + `chroot`；或 Qiling 单二进制 | 需手工修补 rootfs |
| Qiling | Unicorn 手写 harness / AFL++ QEMU 模式 | 工作量显著上升 |
| radare2 | Ghidra 无头 / `objdump` + `nm` + `strings` | 交叉引用需手工 |
| `ida-mcp`（IDA MCP） | `pyghidra-mcp` → Ghidra 无头 → radare2 + binutils | MCP 断链即回到手工追链，效率降一个量级但结论强度不变 |
| `pyghidra-mcp` | Ghidra 无头 `analyzeHeadless` | 需自己写 postScript 抽结果 |
| AFL++ | `honggfuzz`、`libFuzzer`（有源码时） | 二进制模式支持弱 |
| Shodan/Censys | 主动扫描（需授权！） | 法律与噪声风险 |
