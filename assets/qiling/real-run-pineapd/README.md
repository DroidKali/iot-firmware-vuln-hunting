# M4 Qiling 真实执行记录（固件原始 pineapd）

本目录保存 2026-11-02 在 Ubuntu 24.04 服务器上，用真实 Docker、Qiling 1.4.6 与 `scripts/sandbox_run.py` 执行 `scripts/adapter_qiling.py` 的六组原始产物。目标为 Hak5 WiFi Pineapple Nano 固件（OpenWrt 19.07.2）自带的 `/usr/sbin/pineapd`。文件未改写；每个运行产物的大小与 sha256 见 `SHA256SUMS`。

## 结论

- **六组全部失败，没有到达 pineapd 的 main**：六次 `EmulationResult` 均为 `FAILED`（`memory-error`），`sink_hit=0`，没有生成漏洞证据，也没有执行到应用层逻辑。该结果不能用于判断 pineapd 是否存在漏洞，也不能据此判断它安全。
- **目标确实是固件原始二进制**：`pineapd` 为 ELF32 MSB MIPS、动态 musl、解释器 `/lib/ld-musl-mips-sf.so.1`；宿主文件 sha256 与固件 rootfs 内的 `/usr/sbin/pineapd` 完全一致，且 rootfs 来自 `upgrade-2.7.0.bin`。失败原因不是拿错 rootfs，也不是缺 libpcap。
- **失败发生在动态加载阶段**：基础 Qiling 1.4.6 在加载 musl 动态链接器时触发 `UC_ERR_READ_UNMAPPED`；把 open() 的错误返回从 `-1` 改为 `-errno` 后，加载器能继续搜索 libpcap，但随后在 guest 写内存时触发 `UC_ERR_WRITE_UNMAPPED`。TLB 刷新、Unicorn 2.1.2、显式 `LD_LIBRARY_PATH` 都没有改变失败类别。
- **沙箱边界成立**：六组均由 `sandbox_run.py --mode sandbox` 执行，`mode=sandbox`、`host_fallback=false`，网络 `none`、根文件系统只读、`cap-drop=ALL`、`no-new-privileges`、非 root 用户 `65534:65534`；没有宿主机回退。

## 环境

| 项 | 值 |
| --- | --- |
| 宿主 | Ubuntu 24.04.5 LTS，kernel 6.8.0-147-generic，x86_64 |
| Docker | 29.9.2 |
| Qiling | 1.4.6（容器内 Python 3.11.17） |
| 容器用户 | `65534:65534` |
| 固件 | Hak5 Pineapple Nano，OpenWrt 19.07.2，`upgrade-2.7.0.bin` |
| 目标 | `/usr/sbin/pineapd`，143,397 B，ELF32 MSB MIPS，动态 musl |
| 仿真范围 | Qiling 用户态；不覆盖内核、驱动、硬件外设、真实网络 |

运行镜像共五个，均由 `assets/qiling/Dockerfile` 派生：

| 镜像 | image id | 说明 |
| --- | --- | --- |
| `iot-fw/qiling:1.4.6` | `sha256:09364fe0cf153a69459ed3925d36c41ef5ea41da102281e53d29f545e191cda2` | 基础 Qiling 1.4.6 |
| `iot-fw/qiling:1.4.6-patched` | `sha256:a526b0d0f0909a40a3166119893a1bd95c125831c91529e66070adddc4959249` | 把 `__do_open` 异常分支从 `return -1` 改为 `return -e.errno` |
| `iot-fw/qiling:1.4.6-tlb` | `sha256:e3d9c4b561d103b6b55837e4043f064b327913219cdca4d8306f234a9d078a9f` | patched + 映射后刷新 TLB |
| `iot-fw/qiling:1.4.6-uc212` | `sha256:5a03b5154fbd9d1937599ac190247369e944ef4cf91550a2d12ec69ec714cadc` | 基础镜像 + Unicorn 2.1.2 |
| `iot-fw/qiling:1.4.6-p212` | `sha256:55480b50d42f313ad2d5a836b4f29ca77428f0b189ac5d2da809dc37f41fa852` | patched + Unicorn 2.1.2 |

## 输入与哈希

| 对象 | 大小 | sha256 |
| --- | ---: | --- |
| 固件 `upgrade-2.7.0.bin` | — | `c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d` |
| 目标 `rootfs/usr/sbin/pineapd` | 143,397 | `7fd83f7da8b940263b706dbe3849036181cc795d79b747a2f4454c8f935180bf` |
| 运行时依赖 `rootfs/usr/lib/libpcap.so.1` | 193,744 | 见 rootfs 原始文件；本次未单独重算 |

- `rootfs.file_count=2376`（含 409 个符号链接；`find -type f` 为 1967）。
- 解释器：`/lib/ld-musl-mips-sf.so.1`。
- `DT_NEEDED` 顺序：`libpcap.so.1`、`libwifi.so`、`libsqlite3.so.0`、`libstdc++.so.6`、`libgcc_s.so.1`、`libc.so`。
- `/etc/ld-musl-mips-sf.path` 不存在；它是 musl 的可选路径配置文件，不是缺失的库。
- `/lib/libpcap.so.1` 与 `/usr/local/lib/libpcap.so.1` 不存在；实际存在的是 `/usr/lib/libpcap.so.1`。这也是加载器按搜索路径依次尝试的原因。

## 计划与执行

计划（`main/qiling-plan.json`）：

- `plan_id=QPL-e2b04fcbcf05`，`status=ready`，`run_id=RUN-QL-PINEAPD-001`，`intent_id=INT-QL-PINEAPD-001`。
- `target.container_path=/firmware/rootfs/usr/sbin/pineapd`；`rootfs.container_path=/firmware/rootfs`；`guest_argv0=/usr/sbin/pineapd`。
- `argv=[/firmware/rootfs/usr/sbin/pineapd, --debug]`；`trigger_markers=[pineapd.lock]`；`sink_hooks=[openat]`。
- `runtime.image=iot-fw/qiling:1.4.6-patched`；`budget.timeout_s=90`；计划阶段不探测镜像内 Qiling 版本，`runtime.version=unverified`，实际版本由 `qiling-runner.json` 报告为 1.4.6。

执行统一经 `scripts/sandbox_run.py`：

- `mode=sandbox`，`host_fallback=false`；`network=none`；`read-only` 根文件系统；`cap-drop=ALL`；`no-new-privileges`；`user=65534:65534`；`memory=512m`；`cpus=1`；`pids-limit=128`；临时目录 `nosuid,noexec`。
- 固件目录以 `/root/iot-m4/fw:/firmware:ro` 只读挂载；输出目录以读写挂载到 `/out`。
- 容器内命令：`python3 /out/qiling_runner.py --plan /out/qiling-plan.json --out /out`。
- 六组 `sandbox-run.json` 均为 `ok=false`、`exit_code=1`、`timed_out=false`；资源准入均为 `admitted`。

## 六组结果

实际镜像以各目录 `sandbox-run.json` 的 `image` 字段为准。复制过来的 `qiling-plan.json` 仍保留生成计划时的 `runtime.image=iot-fw/qiling:1.4.6-patched`，所以 `base`、`tlb`、`uc212`、`p212` 的计划文件与实际执行镜像不一致；这是原始产物的状态，未改写。

| 目录 | 实际镜像 | plan / run | EmulationResult | 事件 | sink-hit | 失败 PC 与类别 |
| --- | --- | --- | --- | ---: | ---: | --- |
| `main/` | `iot-fw/qiling:1.4.6-patched` | `QPL-e2b04fcbcf05` / `RUN-QL-PINEAPD-001` | `QL-147dbd2ad9ad` | 5 | 0 | `0x482d7e0`，`UC_ERR_WRITE_UNMAPPED` |
| `base/` | `iot-fw/qiling:1.4.6` | 同上 | `QL-240f2c211124` | 2 | 0 | `0x47d6d0c`，`UC_ERR_READ_UNMAPPED` |
| `tlb/` | `iot-fw/qiling:1.4.6-tlb` | 同上 | `QL-09672e7dac0e` | 5 | 0 | `0x482d7e0`，`UC_ERR_WRITE_UNMAPPED` |
| `uc212/` | `iot-fw/qiling:1.4.6-uc212` | 同上 | `QL-bd1be42851bb` | 2 | 0 | `0x47d6cf8`，`UC_ERR_READ_UNMAPPED` |
| `p212/` | `iot-fw/qiling:1.4.6-p212` | 同上 | `QL-5e0f2c509f92` | 5 | 0 | `0x482d7cc`，`UC_ERR_WRITE_UNMAPPED` |
| `ld/` | `iot-fw/qiling:1.4.6-patched` | `QPL-0933b1024a3b` / `RUN-QL-PINEAPD-002` | `QL-426cc2b5ecaa` | 2 | 0 | `0x482d7e0`，`UC_ERR_WRITE_UNMAPPED` |

六组的 `qiling-import.json` 均为 `status=failed`、`result.status=FAILED`、`failure.category=memory-error`、`retryable=false`、`observed>=1`、`sink_hits=0`；每组都生成 3 条 evidence 与 2 条 fact，但这些是目标、运行与失败元数据，不是漏洞证据。

## 主运行事件

`main/qiling-events.jsonl` 的 5 条事件（均为 `enter` 阶段，尚未看到这些 open 的返回值）：

| seq | hook | 参数 | PC | 分类 |
| ---: | --- | --- | --- | --- |
| 1 | `open` | `/etc/ld-musl-mips-sf.path`，flags=532480，mode=438 | `0x4821dd4` | observed |
| 2 | `open` | `/lib/libpcap.so.1`，flags=532480 | `0x47c78a4` | observed |
| 3 | `open` | `/usr/local/lib/libpcap.so.1` | `0x47c78a4` | observed |
| 4 | `open` | `/usr/lib/libpcap.so.1` | `0x47c78a4` | observed |
| 5 | `exception` | `UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED)` | `0x482d7e0` | failure |

事件 2–4 只是加载器按搜索路径尝试打开 libpcap 的 `enter` 记录；事件 5 是 guest 指令引发的 Unicorn 异常。没有到达 `main`，因此没有 pineapd 的应用层事件，也没有 `sink-hit`。

## 失败过程

1. **基础镜像**（`base/`）：加载器先读取可选的 `/etc/ld-musl-mips-sf.path`，随后在 `PC=0x47d6d0c` 触发 `UC_ERR_READ_UNMAPPED`；只产生 2 条事件，尚未搜索 libpcap。Qiling 1.4.6 的 `__do_open` 在捕获 `QlSyscallError` 后返回 `-1`，而 Linux syscall ABI 期望 `-errno`，musl 会把 `-1` 解释为 `EPERM`；这会污染动态加载器的打开结果。
2. **patched 镜像**（`main/`）：把异常分支改为 `return -e.errno` 后，加载器能走到 libpcap 搜索路径，并在 `/usr/lib/libpcap.so.1` 之后于 `PC=0x482d7e0` 执行写内存时触发 `UC_ERR_WRITE_UNMAPPED`。失败点从加载器读取前移到加载器重定位/写内存阶段，仍未到 pineapd 的 `main`。
3. **TLB 变体**（`tlb/`）：在映射后刷新 TLB，事件与失败 PC 和 patched 相同，未修复。
4. **Unicorn 2.1.2 变体**（`uc212/`、`p212/`）：分别基于基础镜像和 patched 镜像替换 Unicorn；`uc212` 仍在 `0x47d6cf8` 触发 `READ_UNMAPPED`，`p212` 仍在 `0x482d7cc` 触发 `WRITE_UNMAPPED`。换 Unicorn 版本没有改变失败类别。
5. **库搜索路径变体**（`ld/`）：使用 patched 镜像并设置 `LD_LIBRARY_PATH=/usr/lib`；事件只剩 `/usr/lib/libpcap.so.1` 一次打开尝试，随后仍在 `0x482d7e0` 触发 `WRITE_UNMAPPED`。这不是 libpcap 找不到的问题。

综合证据只能支持一个结论：当前 Qiling 1.4.6 对这套 musl 动态加载器的映射/重定位处理不完整，导致 pineapd 在进入应用代码前失败。没有证据表明 pineapd 本身有问题，也没有证据表明它安全。

## 复现

以下命令在服务器上执行。重跑会生成新的 plan_id / run_id / emulation_id，不会与本目录的 ID 相同；本目录保存的是当时那次运行的原始输出。

```bash
export REPO=/root/iot-m4/qiling-test/repo
export FW=/root/iot-m4/fw
export TEST=/root/iot-m4/qiling-test

# 1. 生成计划（--arg=--debug，不能写成 --arg --debug）
python3 "$REPO/scripts/adapter_qiling.py" plan --target "$FW/rootfs/usr/sbin/pineapd" --firmware-root "$FW" --rootfs "$FW/rootfs" --run-id RUN-QL-PINEAPD-001 --intent-id INT-QL-PINEAPD-001 --firmware-sha256 c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d --trigger-marker pineapd.lock --sink-hook openat --image iot-fw/qiling:1.4.6-patched --timeout 90 --arg=--debug --json "$TEST/pineapd-plan.json"

# 2. 经 sandbox_run.py 执行并归一化（主运行）
python3 "$REPO/scripts/adapter_qiling.py" run --plan "$TEST/pineapd-plan.json" --out "$TEST/pineapd-out" --sandbox-script "$REPO/scripts/sandbox_run.py" --json "$TEST/pineapd-out/qiling-import.json"

# 3. 其余镜像变体：同一计划，换 --image 与输出目录
python3 "$REPO/scripts/adapter_qiling.py" run --plan "$TEST/pineapd-plan.json" --out "$TEST/pineapd-out-base" --sandbox-script "$REPO/scripts/sandbox_run.py" --image iot-fw/qiling:1.4.6 --json "$TEST/pineapd-out-base/qiling-import.json"
```

`ld/` 的计划额外带有 `LD_LIBRARY_PATH`，需要重新生成计划并在 plan 命令中加 `--env LD_LIBRARY_PATH=/usr/lib`，再用 patched 镜像执行。完整命令与参数以各目录的 `qiling-plan.json`、`sandbox-run.json` 为准，本 README 不复制所有变体命令行。

## 文件表

六个运行目录共 62 个文件；`SHA256SUMS` 覆盖全部 62 个文件（不含本 README 与 `SHA256SUMS` 自身）。关键文件：

| 文件 | 大小 | sha256 | 说明 |
| --- | ---: | --- | --- |
| `main/qiling-plan.json` | 9,360 | `2c557725c20e0ec660f2274f27998798a2d9bfb25398bdb81ac774fffacdda28` | 主运行计划（ready） |
| `main/qiling-import.json` | 15,531 | `5605a91d66938797ec364076d7c08f3fad312e18f23c99fd62526438b4124cbd` | 主运行归一化导入包（failed / FAILED） |
| `main/qiling-runner.json` | 593 | `7e6ee1e684c327efb8c4a9779a0376c87ea21bdf3ba00e459b030afbea3c2b31` | 容器内 runner 报告 |
| `main/qiling-events.jsonl` | 1,321 | `dbc72c1aed0a0dbe634d1c06cc339fb9edf911ed8beabc7b2a0344ce6b7719e9` | 主运行 5 条事件 |
| `main/sandbox-run.json` | 5,095 | `f1bfca0a6bcfcd53e36dbb383b0ffb8c1291c6d6270a9ca5c7f92018199a5cfa` | 主运行沙箱报告 |
| `main/sandbox-run.md` | 3,620 | `08e2faf0882db686a9ffb1995cb389387115e781741937a54a3986259fb246ad` | 主运行沙箱报告（Markdown） |
| `base/qiling-import.json` | 11,834 | `dcc514f36823d25650be31ee81264b746e432b9c9bf20c1ae939bf4b6fd1e15e` | 基础镜像失败导入包 |
| `base/qiling-events.jsonl` | 534 | `a2951c12d7e7097bf0c990c6ecd702f05e498f7dcade5ccd60a45e5ac4c7f56c` | 基础镜像 2 条事件 |
| `ld/qiling-plan.json` | 9,401 | `738891dc82540d10239ca5952bbb435ed0f06eb0fe8063fc5394653a52a9a6eb` | LD_LIBRARY_PATH 计划 |
| `ld/qiling-import.json` | 11,840 | `2fb1921fdfe04df4ecff8562da2455160b25e0735bb94e4923a34108e5d2d9cd` | LD_LIBRARY_PATH 失败导入包 |

每个目录包含：`qiling-plan.json`、`qiling-import.json`、`qiling-runner.json`、`qiling-events.jsonl`、`sandbox-run.json`、`sandbox-run.md`、`qiling-stdout.log`、`qiling-stderr.log`、`sandbox-stdout.log`、`sandbox-stderr.log`；`main/` 与 `base/` 另有人工可读的 `qiling-import.md`。重复的 `qiling_runner.py` 未复制（与仓库脚本相同）。

## 验证边界

1. 六组都是 `FAILED`，没有执行到 pineapd 的 `main`；不能据此判断 pineapd 的行为、漏洞或安全性。
2. `sink_hit=0`；生成的 3 条 evidence / 2 条 fact 是目标、运行、失败元数据，不是漏洞证据，不能升级为 finding。
3. 只覆盖 Qiling 用户态；不覆盖内核、驱动、硬件外设、真实网络与多架构。
4. 只验证 Qiling 1.4.6 与上述五个镜像；换 Qiling 版本、换镜像或换 rootfs 需重新执行并重新记录哈希。
5. 计划的 `target` 与 `rootfs` 均来自真实固件；目标哈希与固件内文件一致。失败原因是仿真器对 musl 动态加载器的限制，不是固件缺失或路径错误。
6. 原始产物来自 `/root/iot-m4/qiling-test/pineapd-out*`；复制到本目录时未改写内容。`SHA256SUMS` 可用于核对。
