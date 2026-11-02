# M4 Qiling 真实执行记录（静态 MIPS 目标）

本目录保存 2026-11-02 在 Ubuntu 24.04 服务器上，用真实 Docker、Qiling 1.4.6 与 `scripts/sandbox_run.py` 执行 `scripts/adapter_qiling.py` 的原始产物。文件未改写；每个文件的 sha256 见文末文件表。

## 结论

- **受控静态目标成功**：真实 Qiling 用户态执行了一个静态链接的 MIPS 大端测试二进制；`openat("/etc/QLTEST")` 命中 trigger marker，产生 1 条 `sink-hit` 事件、1 条 `EmulationResult`（`SUCCESS`）和 3 条 evidence / 3 条 fact；执行经 `sandbox_run.py` 的真实 Docker 隔离，`host_fallback=false`。
- **固件原始 busybox 失败**：同一套链路对固件自带的动态 musl `busybox` 执行失败，`EmulationResult` 为 `FAILED`（`memory-error`，`UC_ERR_WRITE_UNMAPPED`），没有 sink-hit。原因是 Qiling 1.4.6 对该 musl 动态二进制的映射/重定位缺陷，不是本项目适配器伪造的成功。
- **测试目标不是固件漏洞**：静态目标由本目录的 `qltest-static.c` 编译并放入 rootfs 的 `tmp/`，用于验证「沙箱 → Qiling → Hook → 事件过滤 → Evidence → 黑板」链路；它不能证明固件存在漏洞，也不能替代对真实固件二进制的验证。
- **黑板端到端可用**：把 `qiling-import.json` 导入黑板后，evidence 4 / facts 4 / intents 1 / emulation_results 1，`revision=11`，`verify` 通过。

## 环境

| 项 | 值 |
| --- | --- |
| 宿主 | Ubuntu 24.04.5 LTS，kernel 6.8.0-147-generic，x86_64 |
| Docker | 29.9.2 |
| 运行时镜像 | `iot-fw/qiling:1.4.6`，image id `sha256:09364fe0cf153a69459ed3925d36c41ef5ea41da102281e53d29f545e191cda2`，665,506,017 bytes |
| 镜像内容 | `python:3.11-slim` + `qiling==1.4.6`；Python 3.11.17；不含固件 |
| 容器用户 | 65534:65534（与 `sandbox_run.py --user 65534:65534` 一致） |
| 固件 | Hak5 Pineapple Nano，OpenWrt 19.07.2；`upgrade-2.7.0.bin` |
| 编译器 | `gcc-mips-linux-gnu` 12.4.0 |

`assets/qiling/Dockerfile` 只构建运行时；固件由 sandbox 以只读方式挂载到 `/firmware`，输出目录以读写方式挂载到 `/out`。

## 输入与哈希

| 对象 | 大小 | sha256 |
| --- | ---: | --- |
| 固件 `upgrade-2.7.0.bin` | — | `c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d` |
| 动态目标 `rootfs/bin/busybox` | 303,157 | `0fdc7d06b5068d3e80f05b6069eeff9ae70deeb37d254a67b5f297a86ff35716` |
| 静态目标 `rootfs/tmp/qltest-static` | 677,896 | `07c3d5c34ca3d87e5ca9a23a751dfedbcbb1f3aa4dcfbb327185c4b815fe8897` |
| 测试输入 `rootfs/etc/QLTEST` | 17 | `97224af86e4986d85049c73bf2b3ecf0ce98596d87ac4e892d31eadcb255d71f` |
| 测试源码 `qltest-static.c` | 522 | `401731842277f6ce7ab94d57de840a1cc42ee090b2a6430a390eccae533058c9` |

测试输入内容为 `QLTEST-STATIC-OK\n`。静态目标加入 rootfs 后，rootfs 文件数为 2,376；固件哈希仍取原始 `upgrade-2.7.0.bin`，不因测试夹具改变。

## 复现静态目标

以下命令在服务器上执行。`mips-linux-gnu-gcc` 的版本或参数不同会产生不同字节，目标哈希以本记录为准。

```bash
export REPO=/root/iot-m4/qiling-test/repo
export FW=/root/iot-m4/fw
export TEST=/root/iot-m4/qiling-test

# 1. 构建运行时镜像（只需一次）
docker build -t iot-fw/qiling:1.4.6 "$REPO/assets/qiling"

# 2. 编译静态测试目标并放入 rootfs
mips-linux-gnu-gcc -static -o "$FW/rootfs/tmp/qltest-static" "$TEST/qltest-static.c"
printf 'QLTEST-STATIC-OK\n' > "$FW/rootfs/etc/QLTEST"

# 3. 生成 Qiling 计划
python3 "$REPO/scripts/adapter_qiling.py" plan \
  --target "$FW/rootfs/tmp/qltest-static" \
  --firmware-root "$FW" \
  --rootfs "$FW/rootfs" \
  --run-id RUN-QL-REAL-002 \
  --intent-id INT-QL-002 \
  --firmware-sha256 c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d \
  --trigger-marker QLTEST \
  --sink-hook openat \
  --image iot-fw/qiling:1.4.6 \
  --timeout 60 \
  --json "$TEST/static-plan.json"

# 4. 经 sandbox_run.py 执行并归一化
python3 "$REPO/scripts/adapter_qiling.py" run \
  --plan "$TEST/static-plan.json" \
  --out "$TEST/out-static2" \
  --sandbox-script "$REPO/scripts/sandbox_run.py" \
  --json "$TEST/out-static2/qiling-import.json"
```

计划结果：`plan_id=QPL-08263141f96b`，`status=ready`，`arch=mips/32/big`，`interpreter=null`，`needed=[]`，`argv=[/firmware/rootfs/tmp/qltest-static]`，`filters.trigger_markers=[QLTEST]`，`filters.sink_hooks=[openat]`，`budget.timeout_s=60`。

## 静态执行结果

- `qiling-import.json`：`status=parsed`，`result.status=SUCCESS`，`emulation_id=QL-8d0c65ba9f09`。
- `sandbox-run.json`：`mode=sandbox`，`host_fallback=false`，`exit_code=0`，`timed_out=false`，镜像 `iot-fw/qiling:1.4.6`。
- `qiling-runner.json`：`ok=true`，`status=completed`，`qiling_version=1.4.6`，`event_count=1`，guest 退出码 0。
- 事件（`qiling-events.jsonl` 唯一一行）：

```json
{"hook":"openat","mechanism":"syscall","phase":"enter","classified_as":"sink-hit","trigger":true,"args":{"dirfd":4294967196,"flags":8192,"mode":0,"pathname":"/etc/QLTEST"},"context":{"arch":"MIPS","bits":32,"pc":"0x40a38c"},"seq":1}
```

- guest stdout 为 `QLTEST-STATIC-OK`，stderr 为空。
- `qiling-runner.json` 记录 9 条 `hook_errors`：`system/popen/fopen/getenv/strcpy/strcat/sprintf/snprintf/memcpy` 在静态目标中不存在对应符号，安装失败被记为跳过项，不再产生 failure 事件；`openat` 已成功安装。该行为由本次真实测试驱动修正，并由 selftest 第 25 组覆盖。

说明：`qiling-plan.json` 的 `runtime.version` 是 `unverified`，因为计划阶段不探测镜像内 Qiling 版本；实际版本由 `qiling-runner.json` 报告为 1.4.6。

## 黑板导入

在 `RUN-QL-REAL-002` 下先写入目标 evidence / fact 与 intent `INT-QL-002`，再执行：

```bash
python3 "$REPO/scripts/board_store.py" import \
  --workspace "$TEST/board-real" \
  --qiling "$TEST/out-static2/qiling-import.json"
```

导入结果：evidence 新增 3、fact 新增 3、EmulationResult 1；加上种子记录后黑板计数为 evidence 4 / facts 4 / intents 1 / emulation_results 1 / candidates 0，`revision=11`、`event_count=11`，`verify` 返回 `ok=true`、`duplicates=0`。完整快照与事件日志见 `board/audit-board.json` 与 `board/audit-events.jsonl`。

## 动态 busybox 失败

计划：`plan_id=QPL-45fd38653849`，`run_id=RUN-QL-REAL-001`，`intent_id=INT-QL-001`，目标 `/firmware/rootfs/bin/busybox`，`argv=[busybox, cat, /etc/QLTEST]`，trigger `QLTEST`，sink `openat`。

失败过程：

1. 基础 Qiling 1.4.6 在加载 musl 动态链接器时，所有失败的 `open()` 都返回 `-1`。Qiling 的 `qiling/os/posix/syscall/fcntl.py` 在 `__do_open` 捕获 `QlSyscallError` 后 `return -1`，而 Linux syscall ABI 把 `-1` 解释为 `EPERM`，导致 `libgcc_s.so.1` 等依赖被误报为 `Operation not permitted`。
2. 为排除该缺陷，构建 `iot-fw/qiling:1.4.6-patched`：把 `__do_open` 的异常分支改为 `return -e.errno`。补丁后 `libgcc_s.so.1` 能打开，但 guest 在 `PC=0x482d7e0` 执行 `sb` 时仍触发 `UC_ERR_WRITE_UNMAPPED`（写入地址 `0x90023100`）。该地址在 `ql.mem.is_mapped` 与 `ql.uc.mem_regions` 中均显示已映射，从 Hook 调用 `ql.uc.mem_write` 也能写入；失败发生在 guest 指令路径，属于 Qiling/Unicorn 的动态链接映射缺陷。
3. 另试 `iot-fw/qiling:1.4.6-tlb`（在映射后刷新 TLB）以及 Unicorn 2.1.2 镜像，均未改变 `UC_ERR_WRITE_UNMAPPED`。

因此 `dynamic-busybox/qiling-import.json` 为 `status=failed`：`result.status=FAILED`，`failure={category: memory-error, reason: UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED), retryable: false}`，runner `ok=false`、`exit_code=1`、事件 3 条（2 observed、1 failure、0 sink-hit）；sandbox 仍为 `mode=sandbox`、`host_fallback=false`。

该失败只说明当前 Qiling 版本不能执行这个 musl 动态 busybox，不能据此判断 busybox 是否有漏洞，也不能把该结果升级为成功。

## 文件表

静态成功链路：

- `qiling-plan.json` — 9,165 B — `dcf4de0e33791499de59fc3ebe7073587187c4af7b3257b6e1593d8a15a10656` — 计划（ready，`QPL-08263141f96b`）
- `qiling-import.json` — 11,027 B — `dc301d13822279d5442be350629869587aaae0eb2cc6888e18c2dc312a8a6ad4` — 归一化导入包（parsed，SUCCESS）
- `qiling-runner.json` — 1,781 B — `88fcacee1ab6ca117644b04f5059d1abcd2a7eedcdf18f73508a2175d49db30c` — 容器内 runner 报告
- `qiling-events.jsonl` — 268 B — `1d9926d93de64f3d2e147f2baaca153dea6567e1fa1cf958191cdba9a6ae725b` — 原始事件
- `qiling-stdout.log` — 17 B — `97224af86e4986d85049c73bf2b3ecf0ce98596d87ac4e892d31eadcb255d71f` — guest stdout
- `qiling-stderr.log` — 0 B — `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — guest stderr
- `sandbox-run.json` — 3,914 B — `dabe55c82e378052bc343df58daf39cda768693168b4f264a4711e30385c4a4c` — 沙箱执行报告
- `sandbox-run.md` — 2,408 B — `5bbf614a4cc265cbabc1196b42ac5c00be8b1edb4ad23feecdc0a9f54f64fd22` — 沙箱执行报告（Markdown）
- `qltest-static.c` — 522 B — `401731842277f6ce7ab94d57de840a1cc42ee090b2a6430a390eccae533058c9` — 测试源码

动态失败链路（`dynamic-busybox/`）：

- `qiling-plan.json` — 9,237 B — `fd7ed94c8bd7f3b058f70241f0bf903f6ecb640511b0bde7e3ea5e26691a3147` — 计划（ready，`QPL-45fd38653849`）
- `qiling-import.json` — 12,785 B — `e08ef11a46114be0b65b0fc52a907b708c33dbf4c4927d3da701a5810f120df2` — 归一化导入包（failed，FAILED）
- `qiling-runner.json` — 588 B — `9cf52b3dac59c8a0cd3e44befa44d1ad7c5acddbd626c099e419435bd111eb4d` — runner 失败报告
- `qiling-events.jsonl` — 794 B — `a3ddfd5e15ae54e0b8ae420e5517fde52073a2ff7b02348b3ac9b2af7dbe4d79` — 3 条事件
- `sandbox-run.json` — 5,076 B — `fc1451b811aa5e4874b7840ce8e79425efcbef2f9dd72d71eace12564bed4331` — 沙箱执行报告

黑板快照（`board/`）：

- `audit-board.json` — 11,043 B — `dcaaf68fa06da22d2d52f4fec47daa171ec9e133f43de76c5b588485d65ca665` — 最终快照
- `audit-events.jsonl` — 10,403 B — `57aacf4c01df45de735ae6dd1664eee12daf84c8875e67a06858d196253f12cb` — 11 条事件日志

## 验证边界

1. 只验证了一个手工编译的静态 MIPS 目标，不是固件自带二进制；`SUCCESS` 只表示 Qiling 按计划跑完并产生事件，不是漏洞结论。
2. `openat` 命中仅因路径参数包含 trigger marker；`sink-hit` 不等于可利用，仍需按漏洞类型的 `validate_transition` 判据验证。
3. 没有覆盖内核、驱动、硬件外设、真实网络或多架构；Qiling 只模拟用户态。
4. 动态 busybox 的 `FAILED` 是工具链/仿真器限制，不构成对 busybox 的安全性判断。
5. 本记录只对应 Qiling 1.4.6、该镜像与该宿主；换版本、换镜像或换目标需重新执行并重新记录哈希。
6. 原始产物来自 `/root/iot-m4/qiling-test/out-static2`、`out3` 与 `board-real`；复制到本目录时未改写内容。
