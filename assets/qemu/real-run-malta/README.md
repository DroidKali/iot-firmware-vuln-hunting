# M4 真实 rootfs 启动记录（Malta / MIPS BE）

本目录保存一次**真实固件 rootfs** 在 QEMU 中的可复现启动记录，用于验证 ROADMAP M4 的
「至少一个真实 rootfs 启动到 shell/init」验收项。它不是漏洞结论，也不表示厂商原机行为。

## 结论

- 真实 rootfs 在 `malta` 机器、MIPS BE、30 秒观察窗口内启动到 BusyBox `/bin/sh`，
  串口出现 `/ #`；`emu_run.py` 归类为 `SUCCESS`，观察信号 `shell-prompt`。
- 这次启动使用的是 **OpenWrt 19.07.2 Malta 通用内核**，不是固件内的 ath79 厂商内核。
  因此它证明的是「该 rootfs 的用户态可以在这个 QEMU 机器上启动」，不是「厂商固件在
  原硬件上可启动」。
- 厂商 raw 内核单独尝试过：QEMU 拒绝加载（不是 ELF），结构化归类为
  `FAILED / kernel-format`，`retryable=false`。这只说明内核格式与 machine 不匹配，
  **不能据此判断 rootfs 不可用**。

## 输入与哈希

| 对象 | 值 |
|---|---|
| 固件 | `upgrade-2.7.0.bin`，15 MB，sha256 `c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d` |
| 固件识别 | OpenWrt 19.07.2 r10947-65030d81f3；`ar71xx/generic`；`mips_24kc`；Hak5 WiFi Pineapple Nano |
| SquashFS | 偏移 `0x18657c`，大小 13,619,288 字节，sha256 `3a4ca5579281d7f4c0da79479a0915e048cfb0c49b8966bdfb4eca041b968dae` |
| rootfs 目录 | 1,965 个普通文件，42,148,473 字节；清单哈希（emu_plan）`3c58c2ad7e2b6e1b394e27b50aecf1992093254b649e863cb2134f8fd35cc45e` |
| ext2 镜像 | 168 MiB（176,160,768 字节），sha256 `694b7fb80121ecb25ee6754844c3c212f9a454f757b82555b45e63ad790c9173` |
| Malta 内核 | `openwrt-19.07.2-malta-be-vmlinux.elf`，6,088,460 字节，sha256 `de20f4cbb6df11d17058a3fb836b788bae6b4137e9d19df50b3ddd3652e3b7bc` |
| 厂商 raw 内核 | 固件 0x200 处 LZMA 解压，5,147,972 字节，sha256 `5ba87019ed94ae41b1db9b3f59f94355c904fdfb07fabde42d125e396eb957b5` |
| 执行镜像 | `iot-fw/qemu:latest`，image id `sha256:bc01391a65544a28f4e4c3c3ed1ca73fda9f2b2e4dbf595d9b58d75fa3c90d7b` |
| 镜像内 QEMU | 7.2.22（Debian 1:7.2+dfsg-7+deb12u18+b3） |

固件与 rootfs 二进制不纳入仓库；上表哈希与命令足以重新构造输入。`result.json` 里的
`environment.kernel` / `environment.image` / `environment.serial_log` 保留原服务器
`/root/iot-m4` 绝对路径，复制到本目录的文件与 `artifacts[].sha256` 一一对应。

## 环境

- Ubuntu 24.04.5 LTS，内核 6.8.0-147-generic，Docker 29.9.2。
- 未安装 EMBA；只使用 QEMU 与 e2fsprogs。
- 容器：非 root（uid 65534），只读根文件系统，`--network none`，固件 `:ro`，
  输出目录 `:rw`；QEMU `-snapshot`，串口写 `/out/serial.log`。
- 资源：`-M malta -cpu 24Kc -m 512m -smp 1`，QEMU 退出由 30 秒沙箱观察窗口终止。

## 复现命令

以下命令在 Linux + Docker 上执行；路径按实际目录替换。

```bash
# 1) 解出 rootfs（Windows 7z 会丢符号链接，不要用于启动）
unsquashfs -no-xattrs -d /root/iot-m4/fw/rootfs /root/iot-m4/fw/rootfs.squashfs

# 2) 生成整盘 ext2 镜像（无分区表）
truncate -s 168M /root/iot-m4/fw/rootfs-malta.img
mke2fs -q -F -t ext2 -b 4096 -d /root/iot-m4/fw/rootfs /root/iot-m4/fw/rootfs-malta.img
e2fsck -fn /root/iot-m4/fw/rootfs-malta.img

# 3) 只读探测并生成计划（不执行 QEMU）
cd /root/iot-m4/repo
python3 scripts/emu_plan.py \
  --rootfs /root/iot-m4/fw/rootfs \
  --firmware-root /root/iot-m4/fw \
  --kernel /root/iot-m4/fw/openwrt-19.07.2-malta-be-vmlinux.elf \
  --image-out /root/iot-m4/fw/rootfs-malta.img \
  --arch mips --cpu 24Kc --init /bin/sh \
  --run-id RUN-PINEAPPLE-001 --intent-id INTENT-M4-REAL-001 \
  --firmware-sha256 c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d \
  --json /root/iot-m4/plan-malta.json --md /root/iot-m4/plan-malta.md --quiet

# 4) 构建执行镜像（必须包含 MIPS QEMU；只装 qemu-system-misc 不够）
docker build -t iot-fw/qemu:latest assets/qemu

# 5) 沙箱执行（无宿主机回退）
python3 scripts/emu_run.py \
  --plan /root/iot-m4/plan-malta.json \
  --out /root/iot-m4/run-malta \
  --timeout 30 --image iot-fw/qemu:latest \
  --json /root/iot-m4/run-malta/result.json \
  --md /root/iot-m4/run-malta/result.md
```

## 结果（成功）

- `emulation_id`：`EMU-7b2e141b296c`；`status=SUCCESS`；`failure` 不存在。
- `observations`：`console-success / shell-prompt`（串口第 177 行，文本 `/ # `）；
  `kernel-boot / Linux version`。
- `resource_usage`：`duration_s=31.605`，`timeout_s=30`，`exit_code=124`，
  `timed_out=true`；`serial_bytes=11499`（串口文件 UTF-8 字节数 11,675）。
- 串口关键行：`console [ttyS0] enabled`、`EXT4-fs (sda): mounting ext2 file system`、
  `VFS: Mounted root (ext2 filesystem) on device 8:0`、`BusyBox v1.30.1 ... built-in shell`、
  `/bin/sh: can't access tty; job control turned off`、`/ #`。
- `limitations`：达到观察窗口后由沙箱终止；shell 出现不等于进程/服务稳定，未验证网络与服务。

## 厂商内核尝试（失败，保留为证据）

- 计划：`vendor-kernel/plan-vendor.json`，`kernel.format=unknown`，warning
  「内核格式无法识别；QEMU 可能拒绝 -kernel」。
- 执行：`vendor-kernel/result.json`，`EMU-01c2df7e12c6`，`status=FAILED`，
  `failure.category=kernel-format`，`retryable=false`；串口 0 字节。
- QEMU 原始错误：`qemu-system-mips: could not load kernel '/firmware/vmlinux-ath79.bin': The image is not ELF`。
- 解释：ath79 厂商内核不是 Malta 可加载的 ELF；这是格式/machine 不匹配，不是 rootfs
  不可启动。若要在原硬件语义上复验，需要 ath79 对应的 machine 或换用厂商镜像启动链。

## 文件

| 文件 | sha256 | 说明 |
|---|---|---|
| `plan-malta.json` | `7f309d958aae02d8ca3b24f7ca741668e80cab84a363465aac2b158c496d3419` | 成功路径的 `emulation-plan/1.0` |
| `result.json` | `fcf1f0244e343b07390d9884968e6431da7e03ff55e902032b3f34fe238f91bf` | 成功路径 `emulation-result/1.0` |
| `result.md` | `c49e9eba17f76e512f166df2aafee86f5316f6e1def67c7d03a3298ffabc58d7` | 中文结果摘要 |
| `sandbox-run.json` | `679fcc60232ee3e3beaba50b996abe57c3bbdf43c37c935b3611abab99941ffc` | 沙箱执行报告 |
| `sandbox-run.md` | `b803d9f6be487350dd47f293bc1b81f2c30496fa69ac17e957f9bfc0e7f15dd0` | 沙箱 Markdown |
| `serial.log` | `023df23e953edea300463f95798fbeeefd7a6e9c95d3de452eea9acb74958cc1` | 成功串口全文 |
| `vendor-kernel/plan-vendor.json` | `8fac88dffabfb85d88bb1302785aa47387324fd9a12d38b8ed768aea6d8bf609` | 厂商内核计划 |
| `vendor-kernel/result.json` | `fcd7e104e8d841b815572c05bac33f1dd0e04755a5a828d90dcdb4d8ddda5c56` | 失败结果 |
| `vendor-kernel/result.md` | `debd0dd733374713a1e8b1dd84044c17ab679ea2224d41399b9db69dc559c6fc` | 失败摘要 |
| `vendor-kernel/sandbox-run.json` | `9c253018e42b32757f58fab999c1df36e3a2a8a3dd2817fb8013d93eb694ddb6` | 沙箱报告 |
| `vendor-kernel/sandbox-run.md` | `57d8d976a5a227cbc042d7da15c1f00cb24ceffb3a8608cbad7835ca135c3485` | 沙箱 Markdown |

## 验证边界（必须一起读）

- 这是**一次**真实 rootfs 启动记录，不是厂商固件的完整启动；通用 Malta 内核替换了厂商
  ath79 内核，网络为 `none`，没有服务探测或漏洞触发。
- `backend_version` 在 `result.json` 中为 `unverified`（`emu_plan` 未从镜像内取版本）；
  独立执行的 `qemu-system-mips --version` 为 7.2.22，见上表。
- M4 验收的「至少一个真实 rootfs 启动到 shell/init」已满足；Qiling 定向分支仍未实现，
  不能把本记录当作 Qiling 或完整固件仿真的完成证明。
- 本记录只能支持「该 rootfs 在该 QEMU 配置下到 shell」这一事实；不能支持任何漏洞成立、
  服务可利用或原设备行为结论。
