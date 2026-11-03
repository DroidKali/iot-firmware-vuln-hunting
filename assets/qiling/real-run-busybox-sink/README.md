# M4 Qiling 真实执行记录（固件 busybox 动态目标）

本目录保存 2026-11-03 在 Ubuntu 24.04.5 服务器上，用真实 Docker、Qiling 1.4.11 与
`scripts/sandbox_run.py` 执行 `scripts/adapter_qiling.py` 的原始产物。文件未改写；
每个产物的 sha256 见文末文件表。

## 结论

- **固件自带动态目标成功**：固件 rootfs 内的 `/bin/busybox`（MIPS32 大端、musl 动态）
  在 Qiling 1.4.11 中执行 `cat /etc/QLTEST`，guest 退出码 0，stdout 为
  `QLTEST-STATIC-OK`，stderr 为空。
- **sink 命中可复核**：4 条事件中，第 4 条 `open("/etc/QLTEST")` 命中 trigger marker，
  归类为 `sink-hit`；其余 3 条为 loader / libgcc / libc `strcpy` 的 `observed` 事件。
  runner 报告 `ok=true`、`event_count=4`、`hook_errors=[]`、`error=null`。
- **黑板端到端可用**：导入后新增 3 条 evidence / 3 条 fact / 1 条 EmulationResult
  （`QL-a8427b55a4ab`，`SUCCESS`）；加上种子记录后黑板计数为 evidence 4 / facts 4 /
  intents 1 / emulation_results 1，`revision=11`，`verify` 返回 `ok=true`。
- **这不是漏洞结论**：命中只证明 `/etc/QLTEST` 这个参数到达 `open` Hook；不证明
  busybox 可利用、存在漏洞或不安全。Qiling 只覆盖用户态，不覆盖内核、驱动、硬件外设
  与真实网络。

## 与上次记录的关系

上一次提交把 Qiling **1.4.6** 上动态 musl `busybox` 的失败写成固件原始动态目标
普遍失败，并保留了失败产物。本次用同一个固件、同一个目标、同一套 `plan → sandbox_run →
adapter_qiling` 链路，在 **1.4.11** 上复验成功；因此：

- 1.4.6 的失败是**该版本/该镜像**的动态加载问题，不能概括为“Qiling 不支持 musl”或
  “固件动态目标不可执行”。1.4.6 的静态目标成功记录仍保留在
  `assets/qiling/real-run-static/`。
- 旧的 `assets/qiling/real-run-static/dynamic-busybox/` 失败产物已随本次修正删除；
  本目录是动态 busybox 的替代记录。
- 第一次 1.4.11 运行仍出现 `strcpy` Hook 的
  `ImportError: cannot import name 'INTEGER' from 'qiling.os.const'`。原因是 1.4.11 把
  `INTEGER` 改名为 `INT`；`scripts/qiling_runner.py` 已增加兼容分支。本目录是修复后
  重跑的产物，第 3 条事件为可解析的 `strcpy(dest=2146683360, src="u")`，不再带
  `_resolve_error`。

## 环境

| 项 | 值 |
| --- | --- |
| 宿主 | Ubuntu 24.04.5 LTS，kernel 6.8.0-147-generic，x86_64 |
| Docker | 29.9.2 |
| 运行时镜像 | `iot-fw/qiling:1.4.11`，image id `sha256:1842f10b6477d69220299d765dc5a771de05c890975d2f12c53d5f4d5177db08` |
| 镜像内容 | `python:3.11-slim` + 从 GitHub tag `v1.4.11` 安装的 Qiling；Python 3.11.17 |
| 容器用户 | 65534:65534（与 `sandbox_run.py --user 65534:65534` 一致） |
| 固件 | 原始固件包 `upgrade-2.7.0.bin`，rootfs 2,376 个普通文件 |
| 目标 | `/rootfs/bin/busybox`，303,157 字节，MIPS32 大端，musl 动态 |
| 执行命令 | `/firmware/rootfs/bin/busybox cat /etc/QLTEST` |
| test marker | `/etc/QLTEST` 内容为 `QLTEST-STATIC-OK\n` |

镜像构建文件为 `assets/qiling/Dockerfile`。该文件已把默认版本改为 1.4.11，并固定
commit `86c927cb329993b14e2586e04d1dd7a90deee5fb`；本次记录使用的镜像 id 是上述
构建产物，重新构建可能得到不同 image id，但 `qiling.__version__` 必须为 `1.4.11`。

## 输入与哈希

| 对象 | 大小 | sha256 |
| --- | ---: | --- |
| 固件包 `upgrade-2.7.0.bin` | — | `c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d` |
| 目标 `rootfs/bin/busybox` | 303,157 | `0fdc7d06b5068d3e80f05b6069eeff9ae70deeb37d254a67b5f297a86ff35716` |
| 测试输入 `rootfs/etc/QLTEST` | 17 | `97224af86e4986d85049c73bf2b3ecf0ce98596d87ac4e892d31eadcb255d71f` |
| 固件目录清单哈希 | — | `be146f27ed9a9ac90bb1704426e08e7304c380d35063a38d8f2e68e93b39279a` |

固件哈希取原始 `upgrade-2.7.0.bin`，不因测试输入改变。清单哈希由
`sandbox_run.py` 按相对路径排序后计算，跳过 409 个符号链接与 1 个非普通文件，
覆盖 1,973 个文件。

## 复现

以下命令在服务器上执行；`REPO` 指向本仓库检出目录。

```bash
export REPO=/root/iot-m4/qiling-test/repo
export FW=/root/iot-m4/fw
export TEST=/root/iot-m4/qiling-test

# 1. 构建运行时镜像（Qiling 1.4.11 从 GitHub commit 安装）
docker build -t iot-fw/qiling:1.4.11 "$REPO/assets/qiling"

# 2. 只读生成计划：ready 只表示参数齐全，不代表能跑
python3 "$REPO/scripts/adapter_qiling.py" plan \
  --target "$FW/rootfs/bin/busybox" \
  --firmware-root "$FW" \
  --rootfs "$FW/rootfs" \
  --run-id RUN-QL-BUSYBOX-SINK-001 \
  --intent-id INT-QL-BUSYBOX-SINK-001 \
  --firmware-sha256 c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d \
  --arg cat --arg /etc/QLTEST \
  --trigger-marker QLTEST \
  --sink-hook open --sink-hook openat --sink-hook execve \
  --image iot-fw/qiling:1.4.11 \
  --timeout 60 \
  --json "$TEST/busybox-sink-plan.json"

# 3. 经 sandbox_run.py 执行；无宿主机回退
python3 "$REPO/scripts/adapter_qiling.py" run \
  --plan "$TEST/busybox-sink-plan.json" \
  --out "$TEST/busybox-sink-out" \
  --sandbox-script "$REPO/scripts/sandbox_run.py" \
  --image iot-fw/qiling:1.4.11

# 4. 归一化事件并生成 qiling-import/1.0
python3 "$REPO/scripts/adapter_qiling.py" parse \
  --plan "$TEST/busybox-sink-plan.json" \
  --events "$TEST/busybox-sink-out/qiling-events.jsonl" \
  --runner "$TEST/busybox-sink-out/qiling-runner.json" \
  --sandbox "$TEST/busybox-sink-out/sandbox-run.json" \
  --json "$TEST/busybox-sink-out/qiling-import.json" \
  --md "$TEST/busybox-sink-out/qiling-import.md"
```

## 执行结果

- 计划：`plan_id=QPL-6faa8c4bcbbd`，`status=ready`，`arch=mips/32/big`，
  interpreter `/lib/ld-musl-mips-sf.so.1`，needed `[libgcc_s.so.1, libc.so]`。
- 沙箱：`mode=sandbox`，`host_fallback=false`，`exit_code=0`，`timed_out=false`，
  image `iot-fw/qiling:1.4.11`，耗时 4.844 s。
- runner：`ok=true`，`status=completed`，`qiling_version=1.4.11`，`exit_code=0`，
  `event_count=4`，`events_truncated=false`，`hook_errors=[]`，`error=null`。
- 事件：

| seq | mechanism | hook | classified_as | 关键参数 |
| ---: | --- | --- | --- | --- |
| 1 | syscall | open | observed | `/etc/ld-musl-mips-sf.path`，flags 532480 |
| 2 | syscall | open | observed | `/lib/libgcc_s.so.1`，flags 532480 |
| 3 | libc | strcpy | observed | dest 2146683360，src `u` |
| 4 | syscall | open | sink-hit | `/etc/QLTEST`，flags 8192，trigger true |

- guest stdout：`QLTEST-STATIC-OK`；guest stderr：0 字节。
- 归一化：`status=parsed`，events 4 / sink_hits 1 / observed 3 / failure_events 0 /
  parse_errors 0 / evidence 3 / facts 3，`errors=[]`。

## 黑板导入

先把目标 evidence / fact 与 Intent 写入黑板，再导入 Qiling 结果。种子文件在本目录
`inputs/` 下；下列命令中的路径以复制到服务器后的目录为准：

```bash
export REPO=/root/iot-m4/qiling-test/repo
export TEST=/root/iot-m4/qiling-test
export SEED=/root/iot-m4/qiling-test/repo/assets/qiling/real-run-busybox-sink/inputs

python3 "$REPO/scripts/board_store.py" init \
  --workspace "$TEST/board-busybox-sink" \
  --run-id RUN-QL-BUSYBOX-SINK-001 \
  --firmware-sha256 c69629ef90c715600e09f22ef12732c593f886db3b0ed145f549de551c48f79d \
  --phase P4

python3 "$REPO/scripts/board_store.py" add \
  --workspace "$TEST/board-busybox-sink" --kind evidence --file "$SEED/evidence-busybox.json"
python3 "$REPO/scripts/board_store.py" add \
  --workspace "$TEST/board-busybox-sink" --kind fact --file "$SEED/fact-busybox.json"
python3 "$REPO/scripts/board_store.py" add \
  --workspace "$TEST/board-busybox-sink" --kind intent --file "$SEED/intent-busybox-sink.json"

python3 "$REPO/scripts/board_store.py" import \
  --workspace "$TEST/board-busybox-sink" \
  --qiling "$TEST/busybox-sink-out/qiling-import.json"

python3 "$REPO/scripts/board_store.py" verify --workspace "$TEST/board-busybox-sink"
```

导入返回 `board-import/1.0`：evidence added 3 / duplicates 0，facts added 3 /
duplicates 0，result `QL-a8427b55a4ab`；最终 `revision=11`、`event_count=11`、
evidence 4 / facts 4 / intents 1 / emulation_results 1，`verify` 为 `ok=true`、
`duplicates=0`。

## 文件表

执行产物：

- `qiling-plan.json` — 9,288 B — `5b1f9183447ce53af7f3d177706a6549c627b5003c3a6e64d6148cd3cfcdba33` — 计划（ready，`QPL-6faa8c4bcbbd`）
- `qiling-runner.json` — 463 B — `5835e7eb06acf58d8e0edbc874b5b6501c3665fcf49ec8d2099d88cd2be10290` — 容器内 runner 报告
- `qiling-events.jsonl` — 1,001 B — `e6b408cf145fc0178d857014079735a2497b15575a7c5f4a08bb9e894e94e611` — 4 条原始事件
- `qiling-import.json` — 14,535 B — `ca008343aea0a9270c66c089e17d0dc520249480a2c4f834f78b80d0962021e5` — 归一化导入包（parsed，SUCCESS）
- `qiling-import.md` — 732 B — `e7c6232bb77e0411b5ce7a03160437d577041a48ac5cf71940778af0df6a3c51` — 导入摘要
- `qiling-stdout.log` — 17 B — `97224af86e4986d85049c73bf2b3ecf0ce98596d87ac4e892d31eadcb255d71f` — guest stdout
- `qiling-stderr.log` — 0 B — `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — guest stderr
- `sandbox-run.json` — 3,948 B — `424b54f2975e19657420bfac21ac51ee8ac9e160d622b800578cf092a3639242` — 沙箱执行报告
- `sandbox-run.md` — 2,442 B — `eef7c601bfa88f05ac25b68766515168670a13255d67000e7453b40331d212a4` — 沙箱执行报告（Markdown）
- `sandbox-stdout.log` — 160 B — `fa372d3b8653fb65959f99a146e30fb71860df14886d5696c68ccf226be71485` — 沙箱 stdout
- `sandbox-stderr.log` — 463 B — `6fe1f1fbfa92cf9e8a036b20710c66911864011561c1b8273e71e94ca6f5960b` — 沙箱 stderr

黑板与种子：

- `board/audit-board.json` — 12,421 B — `254ec858d172667694cdaa979ffb5c33e7878491ce6c87e25771ef51384ad565` — 最终快照
- `board/audit-events.jsonl` — 11,271 B — `88ad5f594019a0009bb830e293a2eba0de91eac6de14a3788607553a453f3b1b` — 11 条事件日志
- `inputs/evidence-busybox.json` — 654 B — `4f71351dea1ba6197fa8ecfef80816e5e9f07231d86c25b249e95db6279f7fb2`
- `inputs/fact-busybox.json` — 676 B — `4d6d83d0f35c61a51341f4c75a44599c8a3dd058a1563f75de1eb6abf9ce78e3`
- `inputs/intent-busybox-sink.json` — 667 B — `e956f2f859475c29570ce145c3f257a0df1381fcd4446581f6a4176c2e3b4cb7`

## 验证边界

1. 只验证了该固件自带的 `/bin/busybox` 执行 `cat /etc/QLTEST`；没有遍历 busybox 的
   applet，也没有验证网络、服务、内核或驱动。
2. `sink-hit` 只证明 `/etc/QLTEST` 到达 `open` Hook；它不是漏洞，也不证明可利用；
   候选升级仍需按漏洞类型的 `validate_transition` 判据验证。
3. `SUCCESS` 只表示 Qiling 按计划跑完；guest 退出码为 0 也不等于目标安全。
4. 本次只对应 Qiling 1.4.11、该镜像与该宿主；换版本、换镜像或换目标必须重新执行并
   重新记录哈希。
5. 原始产物来自 `/root/iot-m4/qiling-test/busybox-sink-out-clean` 与
   `board-busybox-sink-clean`；复制到本目录时未改写内容。
