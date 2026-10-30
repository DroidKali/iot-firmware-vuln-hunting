# 整机仿真方法论：抽取 EMBA 的判据，不依赖 EMBA

> **定位**：方法论层。目标是把 EMBA / FirmAE 这类整链工具里**真正可复用的判据与顺序**抽出来，用 `qemu-system-*`、`mke2fs`、`ip`、`nft` 等基础工具复现；**不安装、不启动、不依赖 EMBA**（M3 的日志导入是另一条可选路径，与本方法论无关）。
>
> **边界**：本文不绑定解包器、内核版本或网络后端；命令是模板，参数必须按目标替换。它证明的是「在这个仿真环境里发生了什么」，不是「真实设备上一定如何」。

---

## 0. 结论先行

1. **EMBA 的价值不在代码量，而在它把「准备 → 单变量启动 → 读串口 → 修一处 → 再启动」固化成顺序。** 这套顺序可以用几百行脚本复现，不需要它整套模块和镜像。
2. **整机仿真不是「把 QEMU 跑起来」，而是「用最小变量验证一个假设」。** 每次只改一个变量：内核、`root=`、init、磁盘总线、网络后端。
3. **默认路径**：已有 rootfs + 匹配内核 → 只读源目录 → 整盘 ext2 → QEMU TCG → user-mode 网络 → 串口日志 → 结构化证据。
4. **默认预算**：单次 60–120 秒，最多 3–4 次尝试，总计不超过 15 分钟；超过就记 `BLOCKED` / `FAILED` / `TIMED_OUT`，不盲目重跑。
5. **EMBA 的 2000 秒超时、2 GB 内存、TAP/网桥、firmadyne 补丁内核，是它为了批量自动化做的取舍，不是方法本身。** 单目标手工仿真不需要照抄。
6. **先让 `/bin/sh` 起来，再谈服务。** 如果连 shell 都起不来，任何「端口不通」的判断都没有意义。

### 0.1 EMBA 为什么慢

| 它做的事 | 对单目标仿真的影响 | 本文怎么处理 |
|---|---|---|
| 先跑完整分析流水线（P99 / S09 / S115 / L10 等模块） | 大部分时间花在静态扫描和报告，不在启动 | 只取已提取的 rootfs，直接进入仿真 |
| 每个架构准备整套预编译内核、firmadyne 二进制、libnvram | 镜像和依赖重 | 只保留目标架构需要的一个内核；NVRAM 先不动 |
| 每次尝试默认 2000 秒、2 GB 内存 | 失败也要等很久 | 60–120 秒一档，失败即读日志定位 |
| 为多个 init / 多个网络配置反复重建镜像 | 重复拷贝和挂载 | 先做一次镜像，后续只改启动参数或注入脚本 |
| TAP + 网桥 + 多网卡占位 | 需要 root/CAP_NET_ADMIN，环境重 | 单服务优先 user-mode + hostfwd；确实需要 L2 才上 TAP |

---

## 1. EMBA 实际做了什么（只抽方法）

以下行号来自 EMBA 源码，用于说明判据来源，不是要求阅读或复制它的代码。

| 阶段 | EMBA 的做法 | 可复用的判据 | 不要照搬的部分 |
|---|---|---|---|
| 构建可启动镜像 | `create_emulation_filesystem`（`modules/L10_system_emulation.sh:284`）：rootfs 大小 + 400 MB，`fdisk` 建一个分区，`mkfs.ext2`，拷贝 rootfs，修权限/链接，注入 busybox / bash-static / libnvram / preInit / network 脚本 | **镜像必须可写、可挂载、能容纳 rootfs；启动前先修可执行位和解释器** | 400 MB 固定膨胀、firmadyne 专用二进制、chroot 内的 inferFile/inferService 全套 |
| 选择 init | `main_emulation`（`:517`）：从 `firmadyne/init` 读候选，逐个挂载、备份、改写 init，追加 `preInit.sh` / `network.sh` / `run_service.sh` | **init 是启发式候选，不是唯一答案；先原始 init，再 shell 回落** | 一次性注入整套 firmadyne 服务脚本 |
| 启动 | `run_emulated_system` / `run_qemu_final_emulation`（`:2359` / `:2577`）：按架构选 QEMU、machine、kernel、磁盘总线、`root=`、网卡；串口 + telnet + unix socket | **架构决定 QEMU 二进制、machine、kernel 格式、磁盘总线和根设备；这些必须成组匹配** | 2000 秒、2 GB、telnet 4321、多串口、firmadyne 内核参数 |
| 网络 | `setup_network_emulation` / `write_network_config_to_filesystem`（`:2085` / `:2167`）：从固件配置推导 guest IP/接口/网桥/VLAN，创建 TAP，写 `/firmadyne/network_type` 等，guest 内脚本配 IP | **先确定 guest 期望的 IP/接口，再决定 host 侧怎么接；host 地址不能和 guest 冲突** | 默认 TAP + 网桥 + 多网卡占位；单服务不需要 |
| 观测 | `check_online_stat`（`:2631`）与 `write_results`（`:3151`）：ICMP、TCP、nmap、CSV 记录 | **启动成功、进程存在、端口响应是三种不同观察，不能互相替代** | 把 nmap 结果直接当漏洞结论 |
| 失败回退 | `check_qemu_kernel_output` / kpanic 识别 / 换 init 重试 | **读原始串口，按错误改一个变量；不是换工具重跑** | 无限重试 |

**一句话**：EMBA 的方法 = **准备一个最小可启动环境，然后一次只改一个变量，直到能观测到目标行为**。本文把这个过程拆成 P0–P5。

---

## 2. 适用边界

### 2.1 能证明什么

| 观察 | 能证明 | 不能证明 |
|---|---|---|
| 内核启动到 init | 内核、rootfs、`root=`、磁盘总线基本匹配 | 固件业务逻辑正确 |
| 进程存在 | 该二进制在当前 rootfs/依赖下能执行 | 端口对外可达、输入能到 sink |
| 端口响应 | 该服务已监听，且当前网络路径可达 | 存在漏洞、可利用、影响范围 |
| 受控输入到达 sink | 在**这个仿真环境**里，输入路径成立 | 真实设备上一定成立（需真机复核） |

### 2.2 前提

- 有合法授权，且只在本机隔离环境执行。
- 已获得可读的 rootfs（或可提取的固件）；加密/签名固件先走解密，不在本文范围。
- 有一个与目标架构/端序匹配的内核；没有就先去拿或编，不能靠「换个 QEMU 参数」解决。
- 接受「仿真失败」是正常结果：`BLOCKED` / `NOT_APPLICABLE` 不是「没漏洞」。

---

## 3. P0：可行性判定（先算，再跑）

在创建镜像之前，把下面几项写成一张表；任何一项为「未知」都先补，不要直接启动。

| 项 | 怎么查 | 判定 |
|---|---|---|
| 架构 / 端序 / ABI | `readelf -h rootfs/bin/busybox`；`file` 多个 ELF | 决定 QEMU 二进制、machine、内核格式 |
| 动态链接器 / libc | `readelf -l <elf> | grep interpreter`；`ls rootfs/lib rootfs/usr/lib` | 决定 rootfs 是否自洽；缺库先补 |
| init 候选 | `/sbin/init`、`/etc/init.d/rcS`、`/linuxrc`、`/init`、`/etc/inittab` | 决定第一轮 init；没有就用 `/bin/sh` |
| 内核 | 固件自带 `vmlinux` / `zImage` / `bzImage` / `Image`；或外部匹配内核 | **没有内核 = 整机仿真不可开始**，只能走单二进制 |
| 根文件系统类型 | `file`、`unsquashfs -l`、`debugfs -R 'ls -l /'` | ext2/3/4 最省事；squashfs 需先展开或内核支持 |
| 存储/分区假设 | `/etc/fstab`、init 里的 `mount`、`mtd` 分区 | 决定 `root=` 和是否需要假 MTD |
| 网络配置 | `/etc/network/interfaces`、`/etc/config/network`、NVRAM 默认文件 | 决定 guest IP/接口，以及 user-mode 是否够用 |
| 硬件强依赖 | watchdog、GPIO、专用字符设备、加密芯片 | 强依赖 → `BLOCKED` / `NOT_APPLICABLE`，不要硬起 |

**停止条件**：没有内核、架构不支持、rootfs 不完整且无法补、加密未解、硬件依赖无法打桩。命中任一条就记录原因，不要用「再跑一次」代替判定。

---

## 4. P1：rootfs 归一化

### 4.1 先保护原件

```bash
# 源目录只读；所有修改在副本上做
cp -a rootfs rootfs.work
find rootfs.work -type f -print0 | xargs -0 sha256sum > rootfs.sha256
```

不要直接在解包目录上改 init；否则第二次尝试无法回到原始状态。

### 4.2 归一化清单

| 问题 | 处理 | 原因 |
|---|---|---|
| 符号链接断裂 | 保留原链接；只补真正缺失的目标 | 很多固件用绝对链接指向 `/usr/lib` |
| 硬链接丢失 | 用支持硬链接的解包器重解，或 `cp -al` 重建 | 服务资源 404 的常见原因 |
| ELF / 脚本无执行位 | `chmod +x` 到实际需要执行的入口 | 解包工具常丢权限 |
| `/dev/console`、`/dev/null` 缺失 | 启动脚本里 `mknod` 或依赖 devtmpfs | 没有 console 会「卡在 starting init」 |
| `/proc`、`/sys`、`/tmp` 未挂载 | init 里显式 mount | 服务启动时读 `/proc` 失败 |
| `/etc/fstab` 挂载 flash 分区 | 注释掉或改成 fake MTD | 挂载失败会中断 init |
| init 里有 `reboot` / `exit` | 备份后注释或改成继续执行 | 否则内核报「Attempted to kill init」 |
| watchdog 喂狗 | 禁用相关 init 脚本，或提供假 `/dev/watchdog` | 否则 30–60 秒后自动重启 |
| NVRAM / 私有配置 | 优先用固件自带默认值；必要时预置配置文件 | 先不动二进制库，减少变量 |

### 4.3 最小 init（用于证明内核和 rootfs）

先用一个**不依赖固件业务逻辑**的 init，把「内核 + rootfs + 磁盘」这条链路跑通：

```sh
#!/bin/sh
# /firmadyne/preInit.sh —— 最小启动脚本
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts /tmp
mount -t devpts devpts /dev/pts 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
ifconfig lo 127.0.0.1 up 2>/dev/null
echo "[emu] rootfs up: $(uname -a)"
exec /bin/sh
```

启动参数用 `init=/firmadyne/preInit.sh`（或 `rdinit=`，取决于内核是否用 initramfs）。如果 shell 能进，说明内核、磁盘、根设备、console 都已正确；下一步才换回固件 init。

### 4.4 换回固件 init

- **脚本 init**：备份原文件，在开头插入最小挂载和网络初始化，末尾保留原逻辑；不要改原脚本的 `exit` 语义，除非确认它会导致 init 退出。
- **ELF init / 符号链接**：不要直接覆盖；写一个 wrapper，先做挂载，再 `exec` 原 init。wrapper 必须是目标架构可执行的脚本（需要 `/bin/sh`）或静态二进制。
- **候选顺序**：`/sbin/init` → `/etc/init.d/rcS` → `/linuxrc` → `/init` → `/bin/sh`。每轮只换一个候选，记录串口末尾 50 行。

---

## 5. P2：构建磁盘镜像（不依赖 loop 设备）

整机仿真需要块设备。最轻的做法是**整盘一个 ext2**，不建分区表；QEMU 直接把它当 `/dev/sda` 或 `/dev/vda`。

```bash
# 1) 估算大小：rootfs 实际字节 + 64–256 MB 余量
SIZE_MB=$(( $(du -sm rootfs.work | cut -f1) + 128 ))

# 2) 建空文件并格式化，-d 直接把目录树写进去（e2fsprogs >= 1.43）
truncate -s "${SIZE_MB}M" rootfs.img
mke2fs -q -F -t ext2 -b 4096 -d rootfs.work rootfs.img

# 3) 只读检查，不修复
e2fsck -fn rootfs.img
```

- `mke2fs -d` 不需要 mount/loop，普通用户即可；设备节点可能无法保留，启动后由 devtmpfs 补。
- 如果内核只认分区，才建一个分区：`sfdisk` / `parted` 建单分区，`root=/dev/sda1`。不要一开始就上分区表。
- 镜像用 `-snapshot` 启动，避免服务写坏基线；需要保留现场时再复制一份。
- Windows 宿主：在 Docker/WSL 里做上述步骤；QEMU 也建议跑在 Linux 容器里。

---

## 6. P3：启动矩阵（一次只改一个变量）

### 6.1 架构与 QEMU 的对应关系

| 目标 | QEMU | machine | 内核格式 | 磁盘 | 根设备 | 网卡 | console |
|---|---|---|---|---|---|---|---|
| MIPS LE 32 | `qemu-system-mipsel` | `malta` | `vmlinux` | IDE | `/dev/sda`（整盘）或 `/dev/sda1` | `e1000` | `ttyS0` |
| MIPS BE 32 | `qemu-system-mips` | `malta` | `vmlinux` | IDE | 同上 | `e1000` | `ttyS0` |
| MIPS64 LE/BE | `qemu-system-mips64el` / `mips64` | `malta` | `vmlinux` | IDE | 同上 | `e1000` | `ttyS0` |
| ARM32 LE | `qemu-system-arm` | `virt` | `zImage` | virtio-blk | `/dev/vda` | `virtio-net-device` | `ttyAMA0` |
| ARM64 LE | `qemu-system-aarch64` | `virt` | `Image` | virtio-blk | `/dev/vda` | `virtio-net-device` | `ttyAMA0` |
| x86 / x86_64 | `qemu-system-x86_64` | `pc` / `q35` | `bzImage` | IDE/SATA | `/dev/sda` | `e1000` | `ttyS0` |

> 这张表对应 EMBA `run_emulated_system` 的分支；QEMU 版本不同，machine 名称略有差异，用 `qemu-system-<arch> -M help` 确认。

### 6.2 启动参数拆解

| 参数 | 是否必需 | 说明 |
|---|---|---|
| `root=` | 是 | 整盘 ext2 用 `/dev/sda`；virtio 用 `/dev/vda`；有分区才加 `1` |
| `console=` | 是 | MIPS/x86 `ttyS0`；ARM `ttyAMA0`；必须和 `-serial` 对应 |
| `rw` | 建议 | 只读启动会让服务无法写 `/tmp` / 配置 |
| `init=` / `rdinit=` | 是 | 指向最小 init 或固件 init |
| `ignore_loglevel` | 可选 | 让串口保留 early boot 信息 |
| `panic=5` | 可选 | 内核 panic 后自动退出，便于采集 |
| `nandsim.parts=...` | 仅 NAND 目标 | EMBA 用于模拟 NAND 分区；rootfs 在 ext2 磁盘时不需要 |
| `firmadyne.syscall=1` | **不要默认加** | 这是 firmadyne 补丁内核的参数；用发行版/原厂内核时无效甚至报错 |
| `EMBA_NET=` / `EMBA_NVRAM=` | **不要默认加** | EMBA 自己的启动脚本使用；本文的最小 init 不需要 |

### 6.3 尝试阶梯

| 轮次 | 内核 | init | 目的 |
|---|---|---|---|
| 1 | 固件自带内核 | 固件原始 init | 最高保真，观察它自己怎么失败 |
| 2 | 固件自带内核 | 最小 init / `/bin/sh` | 区分「内核/rootfs 问题」与「业务 init 问题」 |
| 3 | 通用匹配内核 | 固件原始 init | 判断是否内核缺驱动/配置 |
| 4 | 通用匹配内核 | 最小 init | 证明 rootfs 本身可启动 |

每轮只改一个变量；把 QEMU argv、串口日志、退出码落盘。**不要在同一轮同时换内核、init 和网络。**

### 6.4 命令模板

ARM64：

```bash
timeout --signal=INT --kill-after=5 120 \
qemu-system-aarch64 -M virt -cpu cortex-a57 -m 512 -smp 1 \
  -kernel Image -drive if=none,file=rootfs.img,format=raw,id=d0 \
  -device virtio-blk-device,drive=d0 \
  -append "root=/dev/vda rw console=ttyAMA0,115200 init=/firmadyne/preInit.sh ignore_loglevel panic=5" \
  -display none -monitor none -serial file:serial.log -no-reboot -snapshot
```

MIPS LE：

```bash
timeout --signal=INT --kill-after=5 120 \
qemu-system-mipsel -M malta -m 512 -smp 1 \
  -kernel vmlinux -drive if=ide,file=rootfs.img,format=raw \
  -append "root=/dev/sda rw console=ttyS0,115200 init=/firmadyne/preInit.sh ignore_loglevel panic=5" \
  -display none -monitor none -serial file:serial.log -no-reboot -snapshot
```

x86_64：

```bash
timeout --signal=INT --kill-after=5 120 \
qemu-system-x86_64 -M pc -m 512 -smp 1 \
  -kernel bzImage -drive if=ide,file=rootfs.img,format=raw \
  -append "root=/dev/sda rw console=ttyS0,115200 init=/firmadyne/preInit.sh ignore_loglevel panic=5" \
  -display none -monitor none -serial file:serial.log -no-reboot -snapshot
```

> 需要交互 shell 时，把 `-serial file:serial.log` 换成 `-serial mon:stdio`，并用 `Ctrl-a c` 切 monitor。自动化场景不要用交互串口。

### 6.5 通用内核的配置要求

如果不用固件自带内核，至少确认这些配置：`CONFIG_EXT4_FS`（或 ext2）、`CONFIG_VIRTIO_BLK` / `CONFIG_ATA`、`CONFIG_E1000` / `CONFIG_VIRTIO_NET`、`CONFIG_SERIAL_8250_CONSOLE` / `CONFIG_SERIAL_AMBA_PL011_CONSOLE`、`CONFIG_DEVTMPFS_MOUNT`。缺一个，症状通常是「VFS: Unable to mount root fs」或「no console」。

---

## 7. P4：网络模型（先 user-mode，后 TAP）

### 7.1 选择顺序

| 需求 | 用哪种 | 原因 |
|---|---|---|
| 从宿主访问 guest 的单个 TCP 服务 | user-mode + `hostfwd` | 不需要 root，不碰宿主网卡 |
| 多个固定端口 | user-mode + 多条 `hostfwd` | 一条命令搞定 |
| UDP 服务 | user-mode + `hostfwd=udp:...` | 先确认协议 |
| guest 绑定固定 IP（如 192.168.0.1） | 先改配置/加 IP 别名；不行再 TAP | hostfwd 只转发到 guest 的 DHCP 地址 |
| VLAN / 广播 / 多网卡 / L2 保真 | TAP + 独立 netns | 需要 CAP_NET_ADMIN；绝不能桥到办公网 |
| 多台 guest 互联 | `-netdev socket` | 不需要 root，适合复现拓扑 |

### 7.2 user-mode 模板

```bash
qemu-system-arm -M virt -cpu cortex-a15 -m 512 \
  -kernel zImage -drive if=none,file=rootfs.img,format=raw,id=d0 \
  -device virtio-blk-device,drive=d0 \
  -append "root=/dev/vda rw console=ttyAMA0,115200 init=/firmadyne/preInit.sh" \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8080-:80,hostfwd=tcp:127.0.0.1:8443-:443 \
  -device virtio-net-device,netdev=n0 \
  -display none -monitor none -serial file:serial.log -no-reboot -snapshot
```

guest 默认看到 `10.0.2.15`，宿主是 `10.0.2.2`。如果服务只监听固件配置里的 `192.168.0.1`，在 guest init 里加：

```sh
ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up
```

但 `hostfwd` 通常只命中 `10.0.2.15`，不保证命中后加的别名；这时要么把服务配置改到 DHCP 地址，要么走 TAP。

### 7.3 TAP + 独立 netns（确实需要 L2 时）

```bash
ip netns add fw-emu
ip link add tap0 type tap
ip link set tap0 netns fw-emu
ip netns exec fw-emu ip addr add 192.168.0.2/24 dev tap0
ip netns exec fw-emu ip link set tap0 up
ip netns exec fw-emu qemu-system-mipsel -M malta ... \
  -netdev tap,id=n0,ifname=tap0,script=no,downscript=no \
  -device e1000,netdev=n0
```

- 宿主地址不要和 guest 冲突；EMBA 的启发式是把 guest IP 的某一段替换成 2/3，本文只要求**同网段、不冲突**。
- netns 内不要接 `br0` / 物理网卡；需要出网时单独加 NAT 规则，默认 `restrict`。
- 结束后删除 netns 和 tap，避免残留。

### 7.4 服务发现

1. 先看 guest 串口：init 是否启动服务、是否 bind 成功。
2. 宿主侧 `nc -zv 127.0.0.1 8080` 或 `curl -v http://127.0.0.1:8080/`。
3. 需要枚举时用 `nmap -Pn -p- 127.0.0.1`（只扫 hostfwd 暴露的端口），不要扫宿主所在网段。
4. 记录「端口开放」和「HTTP 200」是两件事；后者才说明应用层有响应。

---

## 8. P5：观测与证据

### 8.1 三种观察不能互相升级

| 观察 | 证据类型 | 能说明 | 不能说明 |
|---|---|---|---|
| 串口显示 init 启动、进程存在 | `emulation` | 二进制在该 rootfs 下执行过 | 端口可达、输入可达 |
| 宿主 `nc` 到 hostfwd 端口成功 | `dynamic` | 服务监听且网络路径通 | 漏洞存在、参数可控 |
| 受控请求触发 sink | `dynamic` + 触发上下文 | 在该环境里输入到达危险操作 | 真实设备同样成立 |

这与 `references/data-contracts.md` 的 `Fact.type` / `Evidence.type` 一致；`service` / `runtime-process` / `port-response` 不得互升。

### 8.2 必须落盘的字段

- QEMU 完整 argv、QEMU 版本、内核文件 sha256、rootfs 目录摘要、镜像 sha256。
- 启动参数（`root=`、`console=`、`init=`）、网络模式、hostfwd 列表、超时值。
- 串口日志路径 + sha256、退出码、是否超时、清理是否成功。
- 失败原因分类（见 §9），不要只写「起不来」。

### 8.3 EmulationResult 最小示例

```json
{
  "schema": "emulation-result/1.0",
  "emulation_id": "EMU-001",
  "run_id": "RUN-001",
  "intent_id": "I-001",
  "firmware_sha256": "<64-hex>",
  "backend": "qemu-system",
  "backend_version": "8.2.2",
  "status": "PARTIAL",
  "environment": {
    "machine": "virt",
    "kernel_sha256": "<64-hex>",
    "rootfs_image_sha256": "<64-hex>",
    "network": "user",
    "hostfwd": ["tcp:127.0.0.1:8080-:80"]
  },
  "observations": [
    {"type": "boot", "value": "init reached"},
    {"type": "port", "value": "127.0.0.1:8080 open"}
  ],
  "artifacts": [
    {"path": "serial.log", "sha256": "<64-hex>", "size": 12345}
  ],
  "finished_at": "2026-10-29T12:00:00Z",
  "limitations": ["single service only", "user-mode network"]
}
```

字段约束见 `references/data-contracts.md` §15；`FAILED` / `BLOCKED` / `TIMED_OUT` 必须带 `failure`，`PARTIAL` 必须带非空 `limitations`。

**端口开放不是漏洞证据。** 要把候选升到 `validated` / `confirmed`，还要过 `board_transitions.py` 的类型化证据校验：漏洞类型对应的证据类型、判据、触发上下文、同一 run/固件绑定。

---

## 9. 失败分类与下一步

| 串口/现象 | 最可能原因 | 下一步 | 结果状态 |
|---|---|---|---|
| 无任何输出 | console 错、machine 错、内核没加载 | 换 `ttyS0` / `ttyAMA0`；加 `earlycon`；确认 `-kernel` 格式 | `FAILED` |
| `VFS: Unable to mount root fs` | `root=` 错、磁盘总线错、内核缺 ext2/virtio | 换 `/dev/sda` ↔ `/dev/vda`；换 IDE ↔ virtio；确认 `CONFIG_EXT4_FS` | `FAILED` |
| `No init found` | init 路径不存在、架构/解释器不匹配 | 先 `init=/bin/sh`；检查 `readelf -l` interpreter | `FAILED` / `BLOCKED` |
| `Attempted to kill init` | init 脚本退出 / `exit` | 备份并注释 `exit`，wrapper 里 `exec` | `FAILED` |
| `can't load library` | 缺 libc/依赖、用了错的 rootfs | 补库；确认 `LD_LIBRARY_PATH`；不要混用宿主库 | `FAILED` |
| 卡在 `starting init` | `/dev/console` 缺失、inittab tty 错 | 建 `/dev/console`；改 inittab 到 `ttyS0` | `FAILED` |
| 30–60 秒自动重启 | watchdog | 禁用 watchdog init，或假 `/dev/watchdog` | `BLOCKED` |
| 网络不通 | user-mode/固定 IP/hostfwd 不匹配 | 先 guest 内 `ifconfig`/`ip addr`；再换 TAP | `PARTIAL` |
| 服务未监听 | init 未启动、配置错、依赖缺失 | 手动在 shell 里启动服务，读它的 stderr | `PARTIAL` |
| 超时但串口仍在输出 | 启动慢 / 服务阻塞 | 只加一次超时；仍慢则 `TIMED_OUT` | `TIMED_OUT` |
| `Illegal instruction` | CPU model 不匹配 | 换 `-cpu`；MIPS 试 `MIPS64R2-generic` | `FAILED` |
| 加密/签名/私有硬件 | 无法在 QEMU 复现 | 停止，记录 `NOT_APPLICABLE` | `NOT_APPLICABLE` |

**处理原则**：先读串口原文，再改一个变量；不要同时换内核、init、网络。连续两轮同一错误没有新信息，就停止并记录，不要用「再跑一次」消耗预算。

---

## 10. 预算、隔离与清理

| 项 | 默认值 | 说明 |
|---|---|---|
| 单次超时 | 90–120 秒 | 冷启动 + init + 服务；慢启动最多放宽一次 |
| 尝试次数 | 3–4 轮 | 每轮一个变量；超过就停 |
| 总预算 | 10–15 分钟 | 含镜像构建；不含解包 |
| 内存 | 256–512 MB | 小 rootfs 足够；OOM 再调 |
| vCPU | 1 | 避免并发 init 竞态 |
| 磁盘 | rootfs + 64–256 MB | 太小会写满，太大会拖慢拷贝 |
| 加速 | TCG | 跨架构无 KVM；同架构才考虑 KVM |

**隔离**：

- QEMU 进程放在容器或独立 netns；默认不接宿主物理网卡。
- `-snapshot` 启动，源镜像只读；工作目录用临时目录，结束删除。
- 不用 root 跑 QEMU；只有 TAP 需要 `CAP_NET_ADMIN`，且只在 netns 内。
- 结束检查：QEMU 子进程、tap、netns、临时镜像、串口日志都已清理或归档。
- 接入 `sandbox_run.py` 时，QEMU 是容器内的一个命令；镜像构建可在宿主机完成后再只读挂载，避免容器内需要 loop/privileged。

---

## 11. 最小检查清单

**启动前**

- [ ] 授权范围、目标固件 sha256、解包产物 sha256 已记录。
- [ ] 架构/端序/ABI 已确认，QEMU 二进制存在。
- [ ] 内核文件存在且与架构匹配；没有则记录 `BLOCKED`。
- [ ] init 候选、libc、rootfs 完整性已检查。
- [ ] 镜像已用 `e2fsck -fn` 检查。
- [ ] 网络模式已选：user-mode 优先；TAP 只在 netns。
- [ ] 超时、内存、尝试次数已写入计划。

**启动后**

- [ ] 串口日志已保存并计算 sha256。
- [ ] 退出码/超时/清理结果已记录。
- [ ] 只声明实际观察到的层级（启动 / 进程 / 端口 / 输入）。
- [ ] 失败已归类，并写明「缺哪一步才能继续」。
- [ ] 候选状态没有被跳过 `validate_transition` 直接改写。

---

## 12. 落地工具：emu_plan → 镜像 → emu_run

M4 的执行链是「只读探测 → 人工构建镜像 → 沙箱执行」，三步分开。任何一步都不把猜测当结果：计划只说明准备怎么启动，镜像构建只证明文件系统可挂载，执行只证明串口到了哪一层。

### 12.1 生成启动计划（不执行）

```bash
python scripts/emu_plan.py \
  --rootfs ./rootfs --firmware-root ./fw \
  --kernel ./fw/boot/vmlinux --image-out ./fw/rootfs.img \
  --run-id RUN-001 --intent-id INTENT-001 --firmware-sha256 <64位sha256> \
  --json plan.json --md plan.md
```

工具只读扫描 rootfs（ELF 架构、init 候选、inittab、libc、ld.so）与内核格式，输出 `emulation-plan/1.0`。`status=ready` 表示参数齐全，不表示能启动；`status=blocked` 时每个 blocker 都带 `next_action`。`build.commands` 给出 `truncate` / `mke2fs -d` / `e2fsck` 命令，但**计划器不执行它们**。

### 12.2 构建 ext2 镜像

按 `plan.build.commands` 手工执行，或用等价命令：

```bash
truncate -s 256M rootfs.img
mke2fs -q -F -t ext2 -d rootfs rootfs.img
e2fsck -fn rootfs.img
```

整盘一个 ext2，不建分区表；不要用 `-E root_owner` 改变 rootfs 内文件属主。镜像必须落在 `--firmware-root` 下（容器内 `/firmware` 只读挂载），否则计划会报 `IMAGE_OUTSIDE_MOUNT`。

QEMU 执行镜像：

```bash
docker build -t iot-fw/qemu:latest assets/qemu
```

镜像内含 `qemu-system-mips`（MIPS 需要单独安装，`qemu-system-misc` 不含它）/ `qemu-system-misc` / `qemu-system-arm` / `qemu-system-x86` 与 `e2fsprogs`；容器以非 root、只读根文件系统运行，固件只读挂载，串口写 `/out`。构建时执行不带管道的 `qemu-system-mips --version`，缺包会直接令构建失败。

### 12.3 在沙箱里执行

```bash
python scripts/emu_run.py --plan plan.json --out ./out \
  --image iot-fw/qemu:latest --json result.json --md result.md
```

`emu_run.py` 会先复核计划契约、`run_id` / `intent_id` / 固件哈希、镜像是否 ext2 且 sha256 匹配、内核 sha256 匹配；通过后固定以 `--mode sandbox` 调用 `sandbox_run.py`，没有宿主机回退。只想复核、不执行时加 `--check`（不需要 `--out`）。

退出码：`0` SUCCESS、`1` FAILED/PARTIAL、`2` 用法、`3` 计划阻断或 BLOCKED、`4` 策略拒绝、`5` 资源准入拒绝、`124` 超时。计划阻断时仍写一份 `BLOCKED` 结果说明「为什么没跑」，但不启动沙箱。

### 12.4 读结果

结果结构见 `references/data-contracts.md` §15 与 §18.1。要点：

- `observations[].type` 只能是 `emulation`；端口探测不是本工具产出。
- `SUCCESS` 只表示串口出现 console-ready / login / shell / init 启动标记，不等于漏洞，也不等于可以进入动态验证。
- `FAILED` / `BLOCKED` / `TIMED_OUT` 必须带 `failure{category, reason, retryable}`；`PARTIAL` 必须带非空 `limitations`。
- 失败分类优先看 `rootfs-mount`、`no-init`、`init-crash`、`library-missing`、`illegal-instruction`、`kernel-panic`，再考虑 `kernel-format`（内核不是 QEMU 可加载格式）、`boot-no-output`（QEMU 退出但串口为空）与 `timeout`。正常的 `console [ttyS0] enabled` 不是失败信号；真正的 console 不匹配会表现为无输出或卡住。

### 12.5 一次真实启动记录

2026-10-30 在 Ubuntu 24.04.5 + Docker 29.9.2 + QEMU 7.2.22 上，对 Hak5 WiFi Pineapple Nano 的 OpenWrt 19.07.2 rootfs（1,965 个普通文件，ext2 镜像 168 MiB）执行了一次真实启动：

- 计划 `PLAN-e23e2aa53de7`（`emulation-plan/1.0`），结果 `EMU-7b2e141b296c`，`status=SUCCESS`；
- 30 秒观察窗口，实际 `duration_s=31.605`，沙箱以 `exit_code=124` 终止；串口第 177 行出现 `/ #`，观察信号 `shell-prompt`；
- 使用 OpenWrt 19.07.2 Malta 通用内核（sha256 `de20f4...`），**不是固件内的 ath79 内核**；
- 厂商 raw 内核另一轮尝试（`EMU-01c2df7e12c6`）为 `FAILED / kernel-format`，QEMU 报 `The image is not ELF`；这只说明格式/machine 不匹配，不能据此判断 rootfs 不可用。

完整计划、结果、沙箱报告、串口与文件哈希见 `assets/qemu/real-run-malta/README.md`。该记录只证明「该 rootfs 在该 QEMU 配置下用户态启动到 shell」，不证明完整固件启动、厂商原机行为、网络/服务可用或任何漏洞成立。

### 12.6 当前验证边界

- selftest 第 24 组仍用假 sandbox，只验证计划契约、哈希阻断与串口分类，不等于真实 QEMU 启动；
- 真实记录使用的通用内核替代了厂商内核，不能据此推断厂商固件可启动；
- 网络为 `none`，没有服务探测或漏洞触发；`backend_version` 在结果中为 `unverified`（独立测得 QEMU 7.2.22）；
- Qiling 定向分支仍未实现；需要它的场景必须继续标 `BLOCKED` 或转人工，不得用整机 shell 结果代替。

---

## 13. 与现有 skill 的接入

- **Phase 4 的 D1**：先按本文起整机；起不来再按 `references/emulation-fuzzing.md` §3 转 Qiling / qemu-user 单二进制。
- **快速起步**：`references/emulation-fuzzing.md` §2 有最短命令和故障表；本文是完整方法与判据。
- **EMBA 产物**：只有已经跑过 EMBA、手里有日志时，才用 `scripts/adapter_emba.py` 离线导入；**不要为了导入去跑 EMBA**。
- **M4 工具（已落地并有一次真实启动记录）**：`emu_plan.py` 只读探测并生成 `emulation-plan/1.0`（不执行），`emu_run.py` 经 `sandbox_run.py` 执行 QEMU 并输出 `emulation-result/1.0`，二者已接入 `contracts.py`；真实记录见 `assets/qemu/real-run-malta/`。计划 `ready` 只表示参数齐全，串口 `SUCCESS` 只表示观察到 shell/init，二者都不能当成漏洞结论。

---

## 14. 来源与边界

- 流程判据来自 EMBA 的 `modules/L10_system_emulation.sh`（镜像构建、init 选择、启动矩阵、网络配置、观测）与 `helpers/helpers_emba_system_emulation.sh`；只提炼顺序与判据，未复制其源码。
- 具体 QEMU 参数以目标 QEMU 版本的 `-M help` / `-device help` 为准；不同版本 machine 名称可能变化。
- 本文不保证「按命令就能起」：固件差异、内核配置、私有硬件都可能让某一轮失败；失败分类和证据记录本身就是产出。
