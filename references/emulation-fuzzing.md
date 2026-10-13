# 模拟与模糊测试实操

Phase 4 的目标：把 `validated` 的静态链路变成 `confirmed` 的可利用性结论。本文件给出决策树、具体命令、harness 写法与踩坑清单。

## 1. 决策树

```
能否直接从厂商拿到完整 rootfs 且固件是标准 Linux？
├─ 是 → FAT：fat new / extract / analyze / emulate
│        起不来？→ 看 §3 常见故障，逐个补
└─ 否（裸机 / MCU / 私有 RTOS / rootfs 不完整）
   ├─ 目标是单个 ELF（如 /usr/sbin/httpd）？
   │   → Qiling 单二进制 + 依赖打桩（§4）
   ├─ 目标是裸机镜像（.bin + 向量表）？
   │   → fat inspect mcu → Renode / Unicorn 手写 harness / ChipWhisperer（硬件）
   └─ 目标是协议栈 / 私有格式解析？
       → 抽出解析函数 → Unicorn 函数级 harness → AFL++ Unicorn 模式
```

### 1.1 三者不是三选一，是两级

上面的树回答的是「**怎么让代码跑起来**」。但要真正升 confidence，得区分两层：

| 层 | 工具 | 回答的问题 | 产出 |
|---|---|---|---|
| **环境层** | FAT / FirmAE / Qiling / Unicorn harness | 代码**跑不跑得到**？外部输入**到不到 sink**？ | 可达性、参数真值 |
| **引擎层** | AFL++（`-Q` / `-U` / `-O`） | 内存**是否真的会崩**？ | crash + 可控性 |

**串联方式**：环境层先跑通（可手工发一个请求/一次调用触发目标路径），再把同一环境接到 AFL++ 上自动变异。**没有环境层，AFL++ 就是瞎跑**——种子进不了解析逻辑时，覆盖率永远停在启动代码。

**引擎模式怎么选**（决定因素：架构 + 目标能否原生跑 + 有无 syscall 依赖）：

| 模式 | 触发条件 | 相对速度 | 局限 |
|---|---|---|---|
| `-O` FRIDA | 目标**同 arch、能在宿主直接跑** | 快 | 需 ptrace/root |
| `-U` Unicorn | **跨 arch**，且是**纯计算型解析函数**（无 syscall） | 最快 | 必须 harness 把输入写进内存；不能碰文件/网络 |
| `-Q` QEMU | **跨 arch**，且**依赖 libc/文件/socket** | 中 | 需 AFL++ qemu 支持该 arch |
| `-c` CmpLog（叠加） | 目标有 magic / 校验和 / 长度比对拦在入口 | — | 需重编译插桩或 QEMU 模式配合 |

**两个判断先做**：

1. **该不该 fuzz？** 只有 **内存破坏类**（栈/堆溢出、UAF、格式化）才值得开 AFL++。**命令注入 / 认证绕过 / 路径穿越 / 逻辑缺陷不要 fuzz**——它们是「参数到没到 sink」的问题，用 Qiling hook `system`/`open` 直接看参数即可，fuzz 既慢又几乎不可能命中。
2. **目标是网络服务吗？** 是 → 用 Qiling harness 把 socket 输入重定向到文件，再 `afl-fuzz ... -- python3 harness.py @@`（见 §5）。不是 → 直接命令行喂 `@@`。

**判断标准**：只要能在模拟环境里让目标进入「解析外部输入」的代码路径，Phase 4 就算有效。不需要「整机完美运行」。

---

## 2. 整机模拟（FAT / Firmadyne / FirmAE）

### FAT 标准流程

```bash
fat doctor                                     # 先自检，缺工具按提示装
fat new ./firmware.bin                         # 建项目 .fat-projects/<proj>
fat extract .fat-projects/<proj>
fat analyze .fat-projects/<proj>
fat preflight .fat-projects/<proj>             # 预检：缺什么会告诉你
fat emulate --project .fat-projects/<proj>
```

### 起不来时的故障清单（按出现频率排序）

| 症状 | 原因 | 处理 |
|---|---|---|
| 卡在 `starting init` / 无输出 | `/dev/console` 缺失或 inittab 指向不存在的 tty | 建 `dev/console` 字符设备（c 5 1）；或改 inittab 指向 `ttyS0` |
| 服务起不来但 shell 能进 | 缺 `/proc`、`/sys` 挂载 | `mount -t proc proc /proc`；`mount -t tmpfs tmpfs /tmp` |
| `can't load library` | 用错 libc（uClibc vs glibc）、架构不匹配 | 用固件自带的 `lib/`；确认 `qemu-<arch>-static` 与 ELF `Machine` 一致 |
| NVRAM / 配置读取失败 | 依赖私有字符设备或 flash 分区 | Qiling 打桩（`nvram_get` 等），或造一个假的 `/dev/nvram` |
| 看门狗重启 | 未响应 `/dev/watchdog` | 打桩 watchdog feed；或关掉相关 init 脚本 |
| 网络不通 | 默认 `eth0` 未配 | `ifconfig eth0 192.168.1.1 netmask 255.255.255.0 up` |
| 前端资源 404 | 硬链接丢失（解包工具未保留 hardlink） | 用 `unblob`（保留）、或 `cp -al` 重建 |
| 时间相关逻辑错乱 | 2000 年时间 / 无 RTC | `date -s`；打桩 `time()` |
| 起不来且是加密 rootfs | 镜像加密 | 先走解密（找 keys、解密函数），再回 Phase 1 |

**隔离要求**：`fat emulate` 会起真实网络服务，务必：

```bash
# 用独立 network namespace 或 docker network，不要桥接到办公网
docker run --rm --network none -v "$PWD:/data" <fat-image> ...
# 或宿主机上
unshare -n -- bash -c 'fat emulate --project ...'
```

### Firmadyne / FirmAE 补充

FirmAE 的仿真成功率高于 Firmadyne（会自动修补 NVRAM、网络、启动脚本）。当 FAT 起不来且时间允许时，换 FirmAE 交叉验证——**两家都起不来通常说明是加密固件或自定义硬件强依赖，别死磕**。

---

## 3. 单二进制模拟（Qiling）

### rootfs 准备

```bash
# 1) 用固件解出来的真实 rootfs（最省事）
ls rootfs/lib rootfs/usr/lib | head        # 确认 libc 与动态链接器在
# 2) 缺库时用 qiling 官方示例 rootfs
qiling setup
```

### 基本运行

```bash
qltool run -f ./usr/sbin/httpd --rootfs ./rootfs
qltool run -f ./usr/sbin/httpd --rootfs ./rootfs --gdb 127.0.0.1:9999
qltool run -f ./usr/sbin/httpd --rootfs ./rootfs --json      # 结构化输出
```

### Python API 骨架（推荐，可控性强）

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from qiling.os.const import STRING

ROOTFS = "./rootfs"

ql = Qiling(["./rootfs/usr/sbin/httpd"], ROOTFS, verbose=QL_VERBOSE.DEFAULT)

# ---- 1) 打桩：把缺失的硬件/私有接口伪造掉 ----
def fake_nvram_get(ql, name, *rest):
    table = {"model": "AC1200", "sw_version": "1.0.2", "lan_ipaddr": "192.168.1.1"}
    key = name.decode() if isinstance(name, bytes) else name
    return table.get(key.strip("\x00"), "") + "\x00"

# 实际 API 名以 strings/nm 结果为准（常见：nvram_get、nvram_set、envram_get、get_nvram）
try:
    ql.os.set_api("nvram_get", fake_nvram_get, QL_INTERCEPT.CALL)
except Exception as e:
    print("nvram_get 不存在，跳过打桩:", e)

# ---- 2) hook sink，记录参数真值 ----
SINK_ADDR = 0x2A30          # 来自 Layer 3 的静态定位
def on_sink(ql):
    try:
        arg = ql.mem.string(ql.arch.regs.read("r1"))   # ABI 决定寄存器名
        print(f"[SINK HIT] cmd = {arg!r}")
    except Exception as e:
        print("[SINK HIT] 参数读取失败:", e)

# 地址可能因基址不同而漂移，先打印加载基址
print("load base:", hex(ql.loader.load_address))
ql.hook_address(on_sink, ql.loader.load_address + SINK_ADDR)

ql.run()
```

### 常见 API 与踩坑

| 项目 | 说明 |
|---|---|
| `ql.os.set_api(name, cb, QL_INTERCEPT.CALL/ENTER/EXIT)` | 打桩/拦截。**先确认符号真的存在**，否则抛异常（用 try 包住） |
| `ql.hook_address(cb, addr)` | 精确地址 hook。注意地址要加 `ql.loader.load_address`（PIE/基址漂移） |
| `ql.hook_code(cb)` | 指令级 hook，慢，仅用于小范围 |
| `ql.patch(addr, b"\x90\x90")` | 热补丁（跳过校验、强制分支） |
| `ql.mem.read/search/string` | 内存读写 |
| syscall ABI | **MIPS o32 参数在 `a0-a3`，ARM 在 `r0-r3`，x86-64 在 `rdi/rsi/...`**。混用是最常见的坑 |
| `socketcall` | 老 MIPS/ARM 用多路复用 syscall，Qiling 一般能处理；失败时手动 hook `syscall` 号码 |
| 多线程 | Qiling 对线程支持有限，`pthread_create` 常需打桩为同步执行 |
| `fork/exec` | 子进程不会自动跟随；需要 `ql.os.fork` 相关处理或把逻辑改成不走 fork |
| 时间/随机 | `time()`/`getrandom()` 打桩成确定性值，便于复现 |
| 32 位地址空间 | 栈/堆地址与真实设备不同，涉及指针运算的漏洞需谨慎判断 |
| 大端小端 | ELF 的 `Data` 字段决定；Qiling 会按 ELF 自动设置，但手工读内存时要注意 |

### 何时放弃单二进制模拟

- 目标一启动就进 `execve` 链、逻辑全在子进程里
- 目标强依赖真实 flash 布局与 `/proc/mtd` 语义
- 目标是内核模块（需要 Qiling 的 Demigod 或整机模拟）

放弃后降级为「静态链路 + 标注未动态确认」，**不要把静态推测写成 confirmed**。

---

## 4. 手动 QEMU 模拟（Qiling/FAT 都不可用时）

```bash
# user mode + chroot
sudo chroot ./rootfs qemu-arm-static /bin/sh
sudo chroot ./rootfs /usr/bin/qemu-mipsel-static -L ./rootfs ./usr/sbin/httpd

# 需要看 syscall 时
strace -f -e trace=network,execve ./qemu-arm-static ./usr/sbin/httpd

# 抓协议流量
tcpdump -i any -w cap.pcap port 80 &
```

---

## 5. 模糊测试（AFL++）

### 5.1 有源码

```bash
CC=afl-cc AFL_USE_ASAN=1 ./configure --disable-shared && make -j
mkdir in && printf 'GET / HTTP/1.0\r\n\r\n' > in/seed
afl-fuzz -i in -o out -x dict.txt -- ./target @@
```

### 5.2 无源码：三种模式

| 模式 | 参数 | 适用 | 速度 |
|---|---|---|---|
| QEMU | `-Q` | 覆盖面广，最省事 | 慢（~1/5 native） |
| Unicorn | `-U` | 目标能在 Unicorn 里跑起来（纯计算/解析函数） | 中 |
| FRIDA | `-O` | 目标能在宿主 OS 上运行（如 ARM 二进制在 ARM 宿主） | 快 |

```bash
afl-fuzz -Q -i seeds/ -o out/ -- ./usr/sbin/httpd @@
AFL_DEBUG=1 afl-showmap -o map -- ./usr/sbin/httpd @@   # 先确认能拿到覆盖率
```

**前置检查（决定成败）**：
1. `afl-showmap` 能否拿到非空的 map？拿不到说明插桩没生效，别继续跑
2. 种子能让目标走到解析逻辑吗？（用 `strace`/Qiling 确认读到了输入）
3. 目标是 `fork`+多进程模型吗？服务型目标要关掉 fork server（`AFL_NO_FORKSRV=1`）

### 5.3 网络服务的 harness 模式（最常用）

AFL 最适合文件/stdin 输入，网络服务需要把 socket 重定向成文件。

**方案 A：Qiling harness**（推荐，配合 `-Q` 或 Unicorn 模式）

```python
# harness.py —— 把 socket 输入换成文件，然后让目标读这个 fd
import sys, socket, threading
from qiling import Qiling

def run(ql):
    # 1) 创建一个空 socket 对，把 client 端用作输入源
    srv, cli = socket.socketpair()
    with open(sys.argv[1], "rb") as f:          # AFL 提供的 @@ 文件
        data = f.read()
    cli.sendall(data)
    # 2) 打桩 accept/recv，让它从这个 socket 读
    ql.os.set_api("recv", lambda q, *a: srv.recv(a[2] if len(a) > 2 else 4096))
    ql.os.set_api("accept", lambda q, *a: srv.fileno())
    ql.run()

ql = Qiling(["./rootfs/usr/sbin/httpd"], "./rootfs")
run(ql)
```

```bash
afl-fuzz -Q -i seeds/ -o out/ -- python3 harness.py @@
```

**方案 B：`boofuzz` / `Fuzzowski` 做有状态协议模糊**（目标必须真的能起在模拟/真实设备上）

```python
from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.1", 80)))
    s_initialize("req")
    s_string("GET")
    s_delim(" ")
    s_string("/cgi-bin/")       # 变异点
    s_string("ping")
    s_delim("?ip=")
    s_string("1.1.1.1")         # 变异点
    s_static("\r\n\r\n")
    session.connect(s_get("req"))
    session.fuzz()
```

**字典生成**（显著提升命中率）：

```bash
strings -a -n 4 rootfs/usr/sbin/httpd | rg '^[A-Za-z_/=\-]{4,}$' | sort -u > dict.txt
# 协议关键字 + 设备私有参数
rg -i 'cgi|goform|api|cmd|action|soap|hnap' dict.txt
```

> 本机过滤用 `rg`（`grep` 缺失时兜底）；`strings` 本身不变——它读的是目标二进制。

### 5.4 崩溃判定与 triage

```bash
ls out/default/crashes/            # id:000000,sig:11,...
cat out/default/crashes/id:000000* | ./usr/sbin/httpd @@       # 复现
gdb-multiarch ./usr/sbin/httpd core                            # 看 PC / LR / 栈
qltool run -f ./usr/sbin/httpd --rootfs ./rootfs               # 用 Qiling 精确控制复现
afl-tmin -i crash -o min -- ./usr/sbin/httpd @@                # 最小化
```

**判定标准**：

| 现象 | 结论 |
|---|---|
| PC/LR 指向输入数据中的字节（如 `0x41414141`） | 可控，潜在 RCE → 继续做利用（看 NX/PIE/Canary 画像） |
| SIGSEGV 但 PC 指向合法代码地址、无寄存器可控 | 不可控崩溃 → 通常只报 DoS（P3） |
| SIGABRT（`__stack_chk_fail`） | 栈溢出被 Canary 拦住 → 有溢出但需绕过 Canary |
| 超时/挂起 | 可能死锁/无限循环 → DoS |

**不要把 DoS 写成 RCE**，也不要把「崩溃」直接写成「可执行代码」。要写出从崩溃到代码执行的完整条件（可控寄存器、可控内存、绕过 NX/ASLR 的手段）。

### 5.5 模糊的常见误区

- 只跑 30 分钟就下结论「无漏洞」：覆盖率可能只到 3%。用 `afl-whatsup`/`afl-showmap` 看稳定性与覆盖率，配合 `fuzz-reachability` 判断覆盖缺口是真实还是死代码
- 种子质量差：一个空文件当种子，AFL 要花大量时间学协议格式
- 忽略校验和/长度字段：AFL 很难自己算对，需要自定义 mutator 或在 harness 里重算
- 目标有状态机的（先握手才进入解析）：需要 harness 里预置握手序列，或直接用 boofuzz
- 在真实设备上跑模糊：**必须授权且限速**，很多设备会直接砖掉

---

## 6. 硬件接口（必须物理接触时）

### UART 拿 root shell

1. 找 GND（大面积铺铜/电容负极）、TX（空闲高、启动瞬间有数据）、RX（高阻）
2. 常用波特率：`115200`（最常见）→ `57600` → `38400` → `9600`
3. `screen /dev/ttyUSB0 115200` 或 `picocom -b 115200 /dev/ttyUSB0`
4. 启动瞬间按 `Esc`/`Ctrl-C`/`!` 等打断 U-Boot，改 `bootargs`：
   ```
   setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh'
   boot
   ```
5. 得到 shell 后，**先 mount rw**：`mount -o remount,rw /`

### SPI NOR 取固件

```bash
flashrom -p ch341a_spi -r dump.bin          # 读出
flashrom -p ch341a_spi -w new.bin           # 回写
binwalk dump.bin                            # 看结构
```
注意 3.3V/1.8V 电压，以及是否需要在读取前给主控断电（避免总线争用）。

### JTAG / SWD

```bash
# JTAG
jtagulator                     # 自动找引脚
openocd -f interface/ftdi/xxx.cfg -f target/xxx.cfg
# SWD
pyocd list && pyocd commander -t <target>
```

### 故障注入

ChipWhisperer（`cw` 工具链）做电压/时钟毛刺绕过读保护、绕过 Secure Boot 校验分支。属于高级路径，通常只在固件被强加密且无法软件绕过时使用。

---

## 7. Phase 4 的产出要求

每条进入 Phase 4 的候选，必须落到以下三种状态之一并写入 `30-findings-verified.md`：

| 状态 | 含义 | 报告措辞 |
|---|---|---|
| `confirmed-exploitable` | 已复现并证明可控（可执行命令/可读文件/可控 PC） | 「已验证可用」+ 复现步骤 + 证据（日志/截图/hook 输出） |
| `confirmed-vulnerable` | 缺陷存在且可触发，但危害受限（如 DoS、需前置条件） | 「已验证存在，影响为 X」 |
| `unverified-with-reason` | 模拟失败/需硬件/需认证 | 「静态链路完整，未动态验证，原因：X」+ 建议的验证路径 |
