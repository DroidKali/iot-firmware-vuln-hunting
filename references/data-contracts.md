# 数据契约（FirmwareManifest / AuditTask / Candidate / Finding / Evidence / GateResult / SandboxRun / BenchManifest / EmbaImport / 黑板对象 / 执行路径）

本文件定义跨阶段传递的结构化数据，以及**校验入口、版本规则、兼容模式边界**。目标是消除「同一事实在 plan、报告、gate-config 里三种写法」的漂移：任何下游脚本要消费上游产物时，先看 schema 版本，再按本文件取字段。

配套校验器：`scripts/contracts.py`（纯标准库）。`--list` 当前列出 17 种 schema；候选的整文件 envelope 由 `candidates` 文档校验器单独处理。

```bash
# 列出支持的所有 schema
uv run scripts/contracts.py --list

# 校验单个文件（kind 必须是受支持的 schema 名）
uv run scripts/contracts.py --kind firmware-manifest --file 00-manifest.json
uv run scripts/contracts.py --kind candidates --file 10-candidates.jsonl
uv run scripts/contracts.py --kind audit-stages --file 30-stages.json --json 30-stages.check.json

# 退出码：0 全部通过；1 存在字段错误；2 输入/用法错误
```

## 1. 通用规则

| 规则 | 说明 |
|---|---|
| schema 必填 | 每个文档顶层必须有 `schema`，形如 `<kind>/<major>.<minor>`。缺失即视为**未版本化输入** |
| 未知版本拒绝 | 只接受 `contracts.py` 中 `SUPPORTED` 列出的版本；不在表内一律失败，不做「猜字段」降级 |
| 未知字段容忍 | 额外字段允许存在（前向兼容），但**必需字段缺失、类型错误、枚举越界**一律失败 |
| 哈希格式 | 所有 `sha256` 为 64 位小写十六进制，不带 `0x`、不带空格 |
| 路径 | 文档内的相对路径相对**该文档所在目录**解析，不相对 CWD |
| 时间 | ISO 8601 带时区；只写日期时按 UTC 当日 00:00 理解 |
| ID 唯一 | 同一文档内 ID 不得重复，跨文档引用必须能对上。既有前缀：`F-`（Finding）、`C-`（Candidate）、`E-`（Evidence）；黑板另用 `fact_id` / `intent_id` / `hint_id` / `emulation_id` / `event_id`，格式分别为 `FACT-*` / `INT-*` / `HINT-*` / `EMU-*` / `EV-000001` |
| 编码 | UTF-8 无 BOM；JSONL 一行一条，空行与 `#` 注释行允许 |

**版本升级规则**：新增可选字段 → minor +1（旧文档仍合法）；删除字段、改语义、改枚举 → major +1（旧文档必须失败并给出迁移提示）。校验器同时接受同一 major 的相邻 minor（例如 `candidates/1.0` 与 `candidates/1.1`），跨 major 不兼容。

## 2. FirmwareManifest（`firmware-manifest/1.0`）

固件身份的唯一事实源。Phase 0 产出，之后每个阶段都引用它，禁止在报告里另写一份哈希。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `firmware-manifest/1.0` |
| `id` | string | ✅ | 清单 ID，如 `FW-2026-001` |
| `vendor` / `product` / `version` | string | ✅ | 厂商、型号、固件版本 |
| `arch` | enum | ✅ | `mips`/`mipsel`/`arm`/`arm64`/`x86`/`x86_64`/`riscv`/`unknown` |
| `image` | object | ✅ | `{path, sha256, size}`；`path` 相对清单目录 |
| `extracted` | object | — | `{rootfs_dir, method, tool_version}` |
| `source` | object | — | `{url, retrieved_at, notes}` |
| `notes` | string | — | 解包异常、加密分区等 |

门禁用法：`coverage_gate.py --manifest 00-manifest.json [--require-manifest]`。清单存在时校验字段与镜像哈希；`image_verified=false` 表示磁盘文件与清单不符，必须阻断。

## 3. AuditTask（`audit-task/1.0`）

一次审计的范围与预算。Phase 2 依据 `fw_triage.py` 的 `02-tiering.json` 生成（脚本不代写），`contracts.py` 校验，`coverage_gate.py --audit-task` 用它核对「说审了的」和「真审了的」。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `audit-task/1.0` |
| `task_id` | string | ✅ | 任务 ID |
| `manifest_id` | string | ✅ | 指向 FirmwareManifest.id |
| `profile` | enum | ✅ | `light`/`standard`/`strict` |
| `scope` | object | ✅ | `{t1_count, t2_count, skip_count, ealb_total}` |
| `agents` | integer | ✅ | 计划 Agent 数（与 EALB 推导一致） |
| `tiers` | array | — | 每个 T1/T2 文件的 tier 与理由 |
| `created_at` | string | ✅ | 创建时间 |

## 4. Candidate（`candidates/1.0`）

静态扫描与人工分析的候选清单，是**门禁的主要输入**。合法形态有两种：整文件 envelope（strict 下**唯一**合法形态，因为只有它能声明 schema 版本），或 JSONL（每行一条，standard 下便于迭代）。

```json
{"schema": "candidates/1.0", "candidates": [
  {"id": "C-001", "file": "usr/sbin/httpd", "function": "do_ping",
   "sink": "system", "line": 412, "status": "confirmed",
   "evidence": ["E-001"], "source": "sink_scan:command-injection"}
]}
```

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `id` | string | ✅ | `C-###` |
| `file` | string | ✅ | 相对 rootfs 的路径 |
| `sink` | string | ✅ | 危险函数/模式名 |
| `status` | enum | ✅ | 9 态：`hypothesis`/`confirmed`/`not_reproduced`/`not_applicable`/`pending_static_analysis`/`pending_dynamic_validation`/`blocked_by_environment`/`validated`/`not_found` |
| `evidence` | array | confirmed 必需 | 证据 ID 列表，为空则判「无证据」 |
| `line` / `function` | int / string | — | 定位信息 |
| `source` | string | — | 产生该候选的工具与规则 |

**关键约束**：`status=confirmed` 且 `evidence` 为空 → 门禁失败；`status` 不在枚举内 → 失败；同一 `id` 重复 → 失败。非法 JSON 行**不允许静默跳过**：解析错误必须逐行上报（行号 + 原因 + 片段），且该输入判为「解析不完整」，strict 下直接失败。

**`validated` / `confirmed` 的语义**（与 `references/methodology.md` §4 一致）：`validated` = Source→Sink 静态/仿真链路完整闭合、参数可控性与条件已验证，但未动态复现；`confirmed` = 已在模拟或真实设备上复现，是最终态。报告层仍只输出 `CONFIRMED` / `HYPOTHESIS` 两态。黑板上这两个状态不能由报告文案直接写入：必须经 `board_transitions.validate_transition` 做证据绑定、漏洞类型、判据与触发上下文校验（见 §16）。

## 5. Finding（`findings/1.0`）

报告 ④ 区块的机器可读形态。每条漏洞固定 9 字段（与 `references/reporting.md` 一致），缺一即不合格。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `id` | string | ✅ | `F-###` |
| `title` | string | ✅ | 一句话标题 |
| `severity` | enum | ✅ | `critical`/`high`/`medium`/`low`/`info` |
| `confidence` | enum | ✅ | `CONFIRMED`/`HYPOTHESIS` |
| `location` | object | ✅ | `{file, function, line}` |
| `root_cause` | string | ✅ | 根因（不是现象） |
| `impact` | string | ✅ | 可达后果 |
| `evidence` | array | ✅ | 证据 ID，至少一条 |
| `remediation` | string | ✅ | 可执行修复建议 |
| `candidate_id` | string | — | 回指 Candidate，便于追溯处置率 |

`confidence=HYPOTHESIS` 时必须在 `missing_step` 里写明「缺哪一步验证」，否则报告不合格。

## 6. Evidence（`evidence/1.0`）

证据必须可复现：命令、输出、哈希三者齐全，否则只能算「推断」。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `id` | string | ✅ | `E-###` |
| `type` | enum | ✅ | `static`/`dynamic`/`emulation`/`fuzzing`/`manual` |
| `command` | string | ✅ | 实际执行的命令（可复制重跑） |
| `output_excerpt` | string | ✅ | 关键输出片段（保留原始错误文本） |
| `artifact_sha256` | string | — | 产物哈希，有产物时必需 |
| `tool_version` | string | — | 工具与版本 |
| `environment` | string | — | 设备/模拟环境标识 |

动态证据必须注明隔离方式（见 `scripts/sandbox_run.py` 与 `references/emulation-fuzzing.md`）：**在宿主机直接跑未审计固件二进制得到的结论不予采信**。

### 6.1 归一化证据（`evidence/1.1`）

黑板、Qiling/QEMU 与 EMBA 适配器共用同一份证据形态。带 `schema` 的证据**必须**声明 `evidence/1.1`；`evidence/1.0` 只保留为无 schema 的历史轻量形态（`type/path/line|offset/stage/source`），不得给旧对象补一个 `schema` 假装升级。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `evidence/1.1` |
| `evidence_id` | string | ✅ | 证据 ID |
| `run_id` / `firmware_sha256` | string | ✅ | 运行与固件绑定；跨 run 证据不得用于当前候选的验证 |
| `type` | enum | ✅ | `static` / `dynamic` / `emulation` / `fuzzing` / `manual` |
| `observed_at` | string | ✅ | ISO 8601 带时区 |
| `status` | enum | ✅ | `parsed` / `partial` / `failed`；非 `parsed` 必须在 `limitations` 说明缺什么 |
| `source` | object | ✅ | `{type, tool, path?, line?}`；`type` 为 `static`/`dynamic`/`emulation`/`tool-report`/`manual`，`tool` 必填 |
| `artifact` | object | — | `{path, sha256, size?}`，原始产物 |
| `raw_log` | object | — | `{path, sha256}`，原始日志 |
| `hook` | object | — | `{mechanism: syscall|api|libc|other, name}`；`system()` 是 libc/api Hook，`execve` 才是 syscall Hook |
| `filter` | object | — | `{rule_id, rule_version}`，事件过滤规则留痕 |
| `event` | object | 动态/仿真必需 | `{type, trigger?: bool, args?: object}`；`trigger` 表示这次观察是否真触发 |
| `limitations` | array | 非 `parsed` 必需 | 字符串数组 |

约束：`dynamic` / `emulation` 证据必须带 `event`；`static` 证据必须带 `source.path` 或 `artifact`。这些约束由 `contracts.py --kind evidence` 直接执行，避免「只写一句我跑过了」当证据。

## 7. GateResult（`gate-config/1.1`）

`coverage_gate.py --gate-config` 的输出，供 CI 与编排层消费。人类读 `40-coverage.md`，机器读这个文件。

| 字段 | 说明 |
|---|---|
| `schema_version` | `gate-config/1.1` |
| `profile` / `strict` / `gate_version` | 运行配置 |
| `checks` | 每项检查的 `{name, status, detail, required}`，status ∈ `PASS`/`FAIL`/`WARN`/`SKIPPED` |
| `summary` | `{pass, fail, warn, skipped, executed, total, error}` |
| `result` | `pass`/`fail`；仅当无 FAIL、且 strict 下无 required 的 SKIPPED 时为 `pass` |
| `blocked` | **机器可读阻断原因**：`{code, detail}`。code 含 `CHECK_FAILED`、`CHECK_NOT_EXECUTED`、`LAYER1_MISSING`、`LAYER1_CORRUPT`、`LAYER1_NO_INTEGRITY`、`LAYER1_SCHEMA`、`MANIFEST_*`、`STAGE_*`、`CAND_PARSE_ERROR`、`CAND_INPUT_INVALID` |
| `candidate_input` | `{mode, schema, parse_complete, parse_errors, total, reason}`；`mode` ∈ `structured`/`text`/`legacy-text` |
| `scan_integrity` | `{verdict, complete_raw, gaps, unwaived, waived, files_*, engine_verdict}`；未提供时为 `null` |
| `stages` | 各阶段 `{name, status, required, derived}` |
| `inputs` | 每个输入文件的 sha256，用于证明「这份结论对应这份输入」 |

`WARN` 不参与 `result` 判定，但必须出现在报告里：它表示「降级但可继续」，例如结构引擎不可用而退回正则。

## 8. SandboxRun（`sandbox-run/1.1`，兼容 1.0）

不可信固件每次执行的留痕。由 `scripts/sandbox_run.py` 产出，动态证据用它证明「命令确实在隔离环境里跑过」。1.1 增加资源准入（`admission`）；1.0 仍可校验，但缺少准入记录，不得用于证明并发/预算受控。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `sandbox-run/1.1` 或 `sandbox-run/1.0` |
| `mode` | enum | ✅ | `sandbox`（容器）/ `host-opt-in`（显式授权宿主机）/ `check`（只探测）/ `fail-closed`（拒绝执行） |
| `host_fallback` | bool | ✅ | **必须为 false**：隔离不可用只能失败关闭，不得回退宿主机 |
| `command` | array | ✅ | 实际执行的 argv（容器模式含全部隔离参数） |
| `policy` | object | ✅ | 生效的网络/内存/CPU/PID/只读/用户策略 |
| `admission` | object | 1.1 ✅ | 准入决策、策略哈希、请求资源、槽位等待与预算；见 §8.2 |
| `runtime` | object | — | 运行时名、版本、路径、探测结果；`argv` 为实际用于启动运行时的前缀 |
| `mounts.firmware` | object | — | `{path, sha256, read_only, target}`；`sha256` 是目录指纹 |
| `exit_code` / `timed_out` | int / bool | — | 命令退出码与超时标志 |
| `stdout_head` / `stderr_head` | string | — | 有界截断的输出摘要 |

退出码：`0` 成功 / `1` 命令失败 / `2` 用法 / `3` 隔离不可用（fail-closed）/ `4` 策略或授权拒绝 / `5` 资源准入拒绝（排队超时或预算耗尽）/ `124` 超时。

容器模式会为 `--out` 目录补 other rwx + sticky（保留 owner/group 位，通常 0755 → 1757）后再挂载：bind mount 不做 UID 映射，容器内固定以 uid 65534 运行，否则写 `/out` 会 `Permission denied`。host 模式不改用户原目录权限；调整结果写入 `notes`，不属于 `sandbox-run` 契约字段。

### 8.1 SandboxPolicy（`sandbox-policy/1.0`）

由 `scripts/resource_manager.py` 校验，**不在 `contracts.py` 的 17 种 schema 内**。策略是运维配置，不是每次运行的产物；其规范化 JSON 的 sha256 写入 `admission.policy_sha256`，用于证明「这次执行用的是哪份策略」。

| 字段 | 默认 | 约束 | 说明 |
|---|---|---|---|
| `schema` | — | 必填 | `sandbox-policy/1.0` |
| `max_concurrency` | 1 | 1–64 | 同时执行的槽位数；超出排队，**不得先启动再等** |
| `queue_timeout_s` | 300 | 0–86400 | 排队上限；超时报 `QUEUE_TIMEOUT` |
| `max_total_seconds` | 1800 | 1–86400 | 单次请求的墙钟总预算（含排队、探测、执行、清理） |
| `max_timeout_s` | 300 | 1–86400 | 单条命令超时上限，且不得大于总预算 |
| `max_memory_mb` | 1024 | 16–1048576 | 容器内存上限 |
| `max_cpus` | 2.0 | 0.1–256 | CPU 上限 |
| `max_pids` | 256 | 8–1048576 | PID 上限 |
| `allowed_images` | null | null 或非空字符串数组 | 镜像白名单；null 表示不限 |
| `allow_host` | true | bool | 是否允许显式授权的宿主机模式；收紧时设 false |

未知字段直接 `UNKNOWN_FIELD`，不做静默忽略。CLI：`resource_manager.py validate --policy FILE`、`resource_manager.py defaults --json`；退出码 0 合法 / 1 不合法 / 2 用法。

### 8.2 admission（`sandbox-run/1.1`）

| 字段 | 说明 |
|---|---|
| `decision` | `admitted` / `rejected` / `checked` / `queue-timeout` / `budget-exhausted` |
| `code` / `message` | 拒绝或降级的原因；成功时为 null / 空串 |
| `policy` / `policy_sha256` / `policy_source` | 生效策略全文、其 sha256、来源（文件路径或 `defaults`） |
| `request` | `{mode, timeout, memory, cpus, pids, image}`，即本次申请的资源 |
| `slots` | `{limit, slot, wait_s, queued, state_dir}`；`wait_s` 是实际排队时间 |
| `budget` | `{limit_s, used_s, remaining_s}`；`used_s` 从进程启动起算 |

语义：`--check` 只探测、不占槽、不建状态目录；容器模式与显式宿主机模式都先占槽再执行；预算在排队阶段就已消耗，剩余不足 1 秒即拒绝启动。准入拒绝退出码为 5，且 JSON `command=[]`、`exit_code=null`——「没启动」必须能从记录里看出来。

### 8.3 ExecPaths（`exec-paths/1.0`）

`scripts/exec_paths.py` 用 AST 扫描 `scripts/*.py` 的子进程调用，防止新增执行路径绕过统一入口。字段：`schema` / `tool` / `version` / `generated_at` / `root` / `files_scanned` / `total_paths` / `counts` / `ok` / `paths` / `unclassified`。每条 path 记录 `file` / `line` / `api` / `scope` / `call` / `classification` / `input_trust` / `note`。

分类：`sandbox-boundary`（固件执行边界，必须经 `sandbox_run.py`）、`host-static-analyzer`（只解析不可信字节、不执行）、`trusted-metadata`（可信本地元数据）、`test-harness`、`inventory`。出现未知文件即 `unclassified` 并退出 1。当前 16 个脚本共 9 条调用；`sink_scan.py:131` / `sink_scan.py:148` 的 ast-grep / semgrep 仍是 `host-static-analyzer`，是已知残留风险（只解析、不执行）。

## 9. BenchManifest / BenchResult（`bench-manifest/1.0` / `bench-result/1.0`）

检测质量评估的输入与输出，由 `scripts/bench_eval.py` 消费与产出。

**BenchManifest**：`dataset`（名称、版本、kind、license、`real_firmware`）、`splits`（`dev` / `holdout`）、`samples[]`（`id` / `path` / `sha256` / `size` / `files[]` 每个文件的哈希 / `arch` / `kind` / `labels[]`）。每条 label 带 `category`、`file`、`line`、`review`（`reviewed` / `pending`）等；`pending` 标签不参与计分。

**BenchResult**：`schema` / `tool` / `status` / `synthetic` / `generated_at`、`dataset`、`parameters`、`validation`（`status` / `warnings`）、`scope`（`split`、`samples`、`samples_by_split`、`findings_in_scope`、`findings_total`、`labels_total`、`labels_reviewed`、`labels_not_evaluable`）、`confusion_matrix`（`tp`/`fp`/`fn`/`tn`）、`metrics`（`micro` / `macro` / `by_category` / `by_arch` / `by_split`，每项含 precision/recall/F1/FPR/FNR）、`provisional`（`authoritative=false`、`reason`、`labels_included`、`metrics`；标签未复核或存在 `not_evaluable` 样本时必须给出）、`not_evaluable`、`out_of_scope`、`details`（TP/FP/FN 明细）、`baseline`、`exit_code`。**不存在顶层 `split` / `counts` / `micro`**——split 在 `scope.split`，计数在 `confusion_matrix`，指标在 `metrics.micro`。

基线比较用 `--baseline <bench-result.json>`：recall 下降超过 `--max-recall-drop`（默认 0.05）或 FPR 上升超过 `--max-fpr-rise`（默认 0.02）→ `regression=true` 且退出码 **3**（不是 1）。`--strict` 不计算 `provisional`（字段为 null），但仍以 reviewed 标签计分。

## 10. 兼容模式边界（重要）

历史脚本曾接受**纯文本**候选清单（每行一个形如 `C-001` 的 ID）。这类输入无法区分「没有候选」与「解析失败」，因此现在：

| 输入形态 | 判定 | strict 下 |
|---|---|---|
| `candidates/1.0` envelope | `mode=structured` | ✅ 允许 |
| 版本化 JSONL（每行含 `id`/`status`，但无 schema envelope） | `mode=structured` | ❌ 拒绝（`unversioned-input`） |
| 纯文本 ID 行（无 schema） | `mode=text` | ❌ 失败 |
| 纯文本 + `--legacy-text-candidates` | `mode=legacy-text`，报告中披露 | ❌ 失败（显式声明也不放行） |
| 文件缺失 / 读取失败 / 含非法 JSON 行 | `ok=false` | ❌ 失败（`--allow-empty-candidates` 不能豁免） |

`--allow-empty-candidates` 只豁免**合法解析后的空清单**（那是一个真实结论：扫了，确实没有候选），绝不豁免「文件丢了」「JSON 坏了」。strict 下报告必须显式声明本轮候选输入的模式；拿不到模式就当作不合格。

## 11. 迁移清单

从旧产物过渡到上述契约：

1. Phase 0 产出 `00-manifest.json`（`firmware-manifest/1.0`），并给镜像算 sha256。
2. Phase 2 依据 `fw_triage.py` 的 `02-tiering.json` 生成 `20-tasks.json`（`audit-task/1.0`），报告里的覆盖率数字改为引用它。
3. `sink_scan.py` 输出已是 `layer1-sinks/1.3`（含 `scan_integrity.verdict` 与 `engine_status.verdict`），门禁用 `--layer1` 消费。
4. 候选清单在 strict 下必须改为 envelope；带 `status` 的 JSONL 只在 standard 下可用（strict 判 `unversioned-input`）。纯文本输入加 `--legacy-text-candidates` 仅作过渡，且必须在报告里标注。
5. 阶段状态写 `30-stages.json`（`audit-stages/1.0`），必需阶段非 `success` 即阻断。
6. 报告 ④ 区块与 `findings/1.0` 对齐；证据统一引用 `E-###`。
7. 黑板初始化：`board_store.py init --workspace ... --run-id ... --firmware-sha256 ...` 生成 `audit-events.jsonl`（首事件 `BOARD_INITIALIZED`）和 `audit-board.json` 快照；`--phase` 默认 `P0`，只在补录或已确认当前阶段时显式指定。
8. `board_store.py import --workspace ... --manifest ... --layer1 ... --stages ... --candidates ...` 把 Phase 0–5 的结构化产物导入黑板；已有 EMBA 日志时追加 `--emba 05-emba-import.json`。导入只新增 Fact / Evidence / Candidate，不改写原文件；门禁仍读原来的 manifest / layer1 / stages / candidates。
9. 候选状态只能经 `board_store.py transition`（内部调用 `board_transitions.validate_transition`）；回退用 `board_store.py backtrack`，且 `from_phase` 必须等于黑板当前 `phase`。
10. 已有 EMBA 产物先经 `adapter_emba.py parse` 生成 `emba-import/1.0`，再 `board_store.py import --emba`；适配阶段不启动 EMBA、Qiling 或 QEMU。

## 12. 黑板事件与快照（`board-event/1.0`）

黑板有两个文件，职责不同：

- `audit-events.jsonl`：**真相源**，一行一个事件，只追加，不重写。
- `audit-board.json`：**加速器快照**，随时可由事件日志完整重放。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `board-event/1.0` |
| `event_id` | string | ✅ | `EV-000001` 形式，日志内唯一 |
| `run_id` | string | ✅ | 事件所属运行 |
| `seq` | int | ✅ | 从 1 开始连续，回放按它排序与校验 |
| `type` | enum | ✅ | 见下表 |
| `ts` | string | ✅ | ISO 8601 带时区；`ts` 不参与去重键 |
| `dedupe_key` | string | ✅ | `sha256("board-event/1.0\n" + type + "\n" + canonical_json(payload))` |
| `payload` | object | ✅ | 事件载荷 |

| `type` | `payload` 必填 |
|---|---|
| `BOARD_INITIALIZED` | `firmware_sha256`；`manifest_id` 可选 |
| `FACT_RECORDED` | `fact`（完整 `fact/1.0` 对象） |
| `CANDIDATE_RECORDED` | `candidate`（完整候选对象） |
| `EVIDENCE_RECORDED` | `evidence`（完整 `evidence/1.1` 对象） |
| `INTENT_CREATED` | `intent`（完整 `intent/1.0` 对象） |
| `HINT_RECORDED` | `hint`（完整 `hint/1.0` 对象） |
| `EMULATION_RECORDED` | `result`（完整 `emulation-result/1.0` 对象） |
| `CANDIDATE_TRANSITIONED` | `candidate_id` / `from_state` / `to_state` / `reason` / `evidence_refs`；`policy` 可选 |
| `INTENT_STATUS_CHANGED` | `intent_id` / `from_status` / `to_status`；`worker` 可选 |
| `BACKTRACK` | `from_phase` / `to_phase` / `reason` / `evidence_refs`；`approved_by` 可选 |

语义与失败模式：

- 只追加：写入后 `flush` + `fsync`。重复 `dedupe_key` 返回 `duplicate=true` 且不再落盘；回放时同样跳过并计数。
- `seq` 必须从 1 连续；`event_id` 唯一；同一日志出现多个 `run_id` 即 `RUN_MISMATCH`。
- 空行可以容忍（计入 `blank`），但**非法 JSON 行必须报 `PARSE_ERROR` 并非零退出**，不得静默跳过。
- 快照的 `revision` / `event_count` / `last_event_id` 与日志不一致时，`load` 会重建并标记 `recovered=true`；快照缺失也能从日志恢复。
- 重复初始化报 `ALREADY_INITIALIZED`（除非显式 `--force`）；`BACKTRACK` 的 `from_phase` 不是当前阶段报 `PHASE_MISMATCH`，方向不是回退报 `NOT_A_BACKTRACK`。
- 事件载荷内的对象若 `run_id` 与事件不一致，报 `RUN_MISMATCH`；引用不存在的证据 / 来源 / Intent，报 `DANGLING_EVIDENCE` / `DANGLING_REF`。
- 回放遇到状态的 `from_state` 与快照当前状态不一致，报 `STATE_MISMATCH`；未知事件类型报 `UNKNOWN_EVENT`。

## 13. Fact（`fact/1.0`）

Fact 是**有来源、绑定了运行与固件的客观观察**，不是判断，也不是待办。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `fact/1.0` |
| `fact_id` | string | ✅ | 建议 `FACT-*` |
| `run_id` | string | ✅ | 与黑板一致 |
| `firmware_sha256` | string | ✅ | 64 位十六进制 |
| `type` | enum | ✅ | `firmware` / `file` / `elf` / `architecture` / `service` / `config` / `credential` / `syscall` / `api-call` / `network` / `scan` / `stage` / `dependency` / `runtime-process` / `port-response` / `other` |
| `value` | object | ✅ | 非空；字段由 `type` 决定，必须能独立读懂 |
| `evidence_refs` | array | ✅ | 非空字符串数组，指向黑板上已存在的证据 |
| `source` | object | ✅ | `{type, tool?, tool_version?, rule_id?, rule_version?, path?, location?}`；`type` 为 `static` / `dynamic` / `emulation` / `tool-report` / `manual` |
| `observed_at` | string | ✅ | ISO 8601 带时区 |
| `scope` | object | — | 适用范围（架构、镜像、服务等） |
| `supersedes` / `contradicts` | array | — | 字符串数组；被取代/冲突的事实 ID |

约束：`value` 不得为空对象；`evidence_refs` 不得为空；`evidence_refs` 指向的证据必须存在于黑板，否则 `DANGLING_REF`。导入 manifest / layer1 / stages 各产生一条 Fact 和一条证据，ID 由文件哈希派生，重复导入保持幂等。

## 14. Intent（`intent/1.0`）与 Hint（`hint/1.0`）

Intent 是**尚未执行的方向**：必须由已有事实/候选/证据/Intent 触发，带唯一去重键与预算。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `intent/1.0` |
| `intent_id` | string | ✅ | 建议 `INT-*` |
| `run_id` / `firmware_sha256` | string | ✅ | 运行与固件绑定 |
| `type` | enum | ✅ | `triage` / `static-analysis` / `dynamic-validation` / `emulation` / `verification` / `manual-review` / `other` |
| `status` | enum | ✅ | `open` / `claimed` / `done` / `failed` / `cancelled` |
| `from` | array | ✅ | 非空；引用 Fact / Candidate / Evidence / Intent |
| `description` | string | ✅ | 要做什么、为什么 |
| `dedupe_key` | string | ✅ | 幂等键；同一方向不得重复建单 |
| `creator` / `created_at` | string | ✅ | 创建者与时间 |
| `target` | string/object | ✅ | 非空；目标文件、服务、函数或对象 |
| `params` | object | — | 执行参数 |
| `budget` | object | — | `{seconds, max_attempts, tokens}`，均为非负整数 |
| `timeout_seconds` / `max_retries` | int | — | 分别 ≥1 / ≥0 |
| `preconditions` / `stop_conditions` / `expected_outputs` | array | — | 字符串数组 |
| `worker` | string/null | — | 认领者 |
| `claimed_at` / `concluded_at` | string | 条件 | `claimed` 必须有 `worker`+`claimed_at`；`done`/`failed`/`cancelled` 必须有 `concluded_at` |

Intent 状态机：`open → claimed | cancelled`；`claimed → done | failed | cancelled | open`（释放）；`done` / `failed` / `cancelled` 为终态。认领必须带 `worker`，否则 `MISSING_WORKER`；非法转换报 `ILLEGAL_TRANSITION`。

Hint 是人工判断或提示，**不是证据**，不得用来替代 Fact / Evidence。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `hint/1.0` |
| `hint_id` | string | ✅ | 建议 `HINT-*` |
| `run_id` / `firmware_sha256` | string | ✅ | 运行与固件绑定 |
| `content` | string | ✅ | 提示内容 |
| `creator` / `created_at` | string | ✅ | 创建者与时间 |
| `active` | bool | — | 是否仍生效 |
| `affects` | array | — | 受影响的 Fact / Candidate / Intent ID |

## 15. EmulationResult（`emulation-result/1.0`）

Qiling / QEMU / 其他后端共用一份结果契约。关键点是**失败、阻断、超时不能被写成「没发现」**。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `emulation-result/1.0` |
| `emulation_id` | string | ✅ | 建议 `EMU-*` |
| `run_id` / `intent_id` | string | ✅ | Intent 必须存在于黑板 |
| `firmware_sha256` / `target_sha256` | string | 前者必需 | 固件与可执行目标哈希 |
| `backend` / `backend_version` | string | ✅ | 后端名与版本 |
| `status` | enum | ✅ | `SUCCESS` / `PARTIAL` / `FAILED` / `BLOCKED` / `NOT_APPLICABLE` / `TIMED_OUT` |
| `environment` | object | ✅ | 根文件系统、内核、架构、外设等 |
| `observations` | array | — | 结构化观察（对象数组） |
| `evidence_refs` / `artifacts` | array | — | 证据引用；产物 `{path, sha256, size?}` |
| `resource_usage` | object | — | 时间、内存、CPU 等 |
| `started_at` / `finished_at` | string | `finished_at` 必需 | ISO 8601 |
| `limitations` | array | PARTIAL 必需 | 未覆盖内容，不得折叠成成功 |
| `failure` | object | 失败态必需 | `{category, reason, retryable}`，`retryable` 为布尔 |

约束：`FAILED` / `BLOCKED` / `TIMED_OUT` 必须带 `failure`；`PARTIAL` 必须带非空 `limitations`。`SUCCESS` 只表示「后端按预期跑完」，仍需与证据链、类型判据一起才能升级候选状态。

## 16. BoardState（`board-state/1.0`）与候选状态机

BoardState 是快照文件的结构，所有条目都必须绑定同一个 `run_id` 与 `firmware_sha256`。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `board-state/1.0` |
| `run_id` / `firmware_sha256` | string | ✅ | 快照级绑定 |
| `revision` / `event_count` | int | — | 非负；与事件日志对账 |
| `updated_at` | string | ✅ | ISO 8601 |
| `phase` | enum | — | `P0`…`P5`；默认 `P0` |
| `manifest_id` / `last_event_id` | string | — | 清单与最后事件 |
| `evidence` / `facts` / `candidates` / `intents` / `hints` / `emulation_results` / `backtracks` | array | ✅ | 七类数组；每项走对应 validator |
| `counters` | object | — | 若提供，必须与各数组实际长度一致 |

交叉引用（悬空即 `DANGLING_REF`）：`fact.evidence_refs` 必须指向 `evidence`；`intent.from` 必须指向 facts / candidates / evidence / intents；`emulation_result.intent_id` 必须指向 `intents`；`emulation_result.evidence_refs` 与 `backtrack.evidence_refs` 必须指向 `evidence`。每类 ID 在各自数组内唯一。

**BACKTRACK** 记录：`{from_phase, to_phase, reason, evidence_refs, approved_by?}`。`from_phase` 必须等于黑板当前 `phase`，且 `to_phase` 必须是更早的阶段，否则 `PHASE_MISMATCH` / `NOT_A_BACKTRACK`。

候选状态转换白名单（`board-transitions/1.0`）：

| 当前状态 | 允许转到 |
|---|---|
| `hypothesis` | `pending_static_analysis` / `not_applicable` / `blocked_by_environment` |
| `pending_static_analysis` | `pending_dynamic_validation` / `validated` / `not_found` / `not_reproduced` / `not_applicable` / `blocked_by_environment` |
| `pending_dynamic_validation` | `validated` / `confirmed` / `not_reproduced` / `blocked_by_environment` / `not_applicable` |
| `validated` | `confirmed` / `not_reproduced` / `blocked_by_environment` |
| `blocked_by_environment` | `pending_static_analysis` / `pending_dynamic_validation` / `not_applicable` |

终态：`confirmed` / `not_found` / `not_reproduced` / `not_applicable`。`VERIFIED` 是 `confirmed` 的别名（持久化只写小写状态）；同状态转换报 `SAME_STATE`，终态再转报 `TERMINAL_STATE`。

进入 `validated` 或 `confirmed` 时，`validate_transition` 按候选的漏洞类型（`policy.vuln_type`）检查证据绑定与判据：

- 证据必须来自同一 `run_id` 与同一固件；跨 run → `EVIDENCE_NOT_BOUND_TO_RUN`，固件不一致 → `FIRMWARE_MISMATCH`，目标哈希不一致 → `TARGET_HASH_MISMATCH`。
- 至少一条证据的 `type` 属于该漏洞类型允许的来源；否则 `EVIDENCE_TYPE_NOT_ACCEPTED`。
- `policy.criteria` 必须覆盖该类型的 `required_criteria` 且全为 true；缺失 → `VALIDATION_CRITERIA_NOT_MET`。
- 需要触发上下文的类型（命令注入、缓冲区溢出、路径穿越、认证绕过、SSRF、反序列化）必须有 `event.trigger=true`、匹配的触发事件，或候选自带 `trigger` / `poc`；否则 `MISSING_TRIGGER_CONTEXT`。
- `policy.expected` 与 `policy.actual` 要么都给且相等，要么都不给；只给一方 → `EXPECTED_ACTUAL_NOT_SUPPORTED`。
- 其余失败码：`BAD_CANDIDATE` / `BAD_STATE` / `ILLEGAL_TRANSITION` / `TYPE_RULE_MISSING` / `CANDIDATE_TYPE_MISMATCH` / `EVIDENCE_REQUIRED` / `EVIDENCE_INVALID`；成功为 `OK`。

**风险处置不是状态**：`accepted` / `mitigated` / `transferred` / `avoided` / `pending` 是独立字段；`ACCEPTED_WITH_RISK` 只能作为风险处置，写进 `candidate.status` 会被拒绝（`RISK_AS_STATUS`）。接受风险不改变漏洞是否真实存在。

## 17. EmbaImport（`emba-import/1.0`）

EMBA 日志的**离线**解析结果，由 `scripts/adapter_emba.py parse` 产出。适配器不启动 EMBA、Qiling 或 QEMU，也不执行固件字节；它只读取日志文件并把可复核的观察转成 Fact / Evidence。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `emba-import/1.0` |
| `adapter` | object | ✅ | `{name, version}`，解析器自身版本 |
| `run_id` | string | ✅ | 与黑板、证据一致；跨 run 不得导入 |
| `firmware_sha256` | string | ✅ | 64 位十六进制；由 CLI 显式给出，日志本身不能独立证明固件身份 |
| `tool` | object | ✅ | `{name, version}`，来自 F50 的 `EMBA_version` 首 token |
| `expect_version` | string/null | — | 本次 `--expect-version`；不符时 `EMBA_VERSION_MISMATCH` |
| `status` | enum | ✅ | `parsed` / `partial` / `failed` |
| `inputs` | array | ✅ | 每个被读取日志的 `{path, role, sha256, size}`；`path` 相对日志根 |
| `observations` | array | ✅ | `{fact_id, type, observation}`，与 `facts` 一一对应 |
| `facts` | array | ✅ | 完整 `fact/1.0`，全部绑定同一 `run_id` / `firmware_sha256` |
| `evidence` | array | ✅ | 完整 `evidence/1.1`，每条 Fact 至少引用一条 |
| `errors` | array | ✅ | `{code, message, path}`；`parsed` 时为空 |
| `limitations` | array | ✅ | 适用范围与未核对项；无固件文件时声明哈希为 operator-supplied |
| `requirements` | object | — | `{required, satisfied, missing}`；角色限于 `p99` / `s09` / `l15` / `l10` / `s115`；`missing` 非空时 `status` 必须为 `failed` |
| `counts` | object | ✅ | `{evidence, facts, errors, by_type, static-discovery, runtime-process, port-response}`，必须与实际数组一致 |

### 17.1 三类观察不可互升

| 观察 | 日志来源 | `Fact.type` | `value.observation` | 证据 `type` | 语义 |
|---|---|---|---|---|---|
| 静态发现 | L15 / S09 | `service` | `static-discovery` | `static` | 固件里存在该服务/组件，**没有**运行证据 |
| 仿真进程输出 | S115 | `runtime-process` | `runtime-process` | `emulation` | 用户态仿真中该二进制实际产生输出 |
| 端口响应 | L10 | `port-response` | `port-response` | `dynamic` | 系统仿真中该 IP/端口实际响应 |

其余静态事实（`firmware` / `elf` / `file` / `architecture` / `dependency` / `stage`）的 `value.observation` 固定为 `static-discovery`。P99 的 ELF 落成 `elf`，PE32 落成 `file` 且 `value.format=PE32`；两者不能混写。任何把 `service` 的 observation 改成 `runtime-process`、或把静态证据挂到 `port-response` 的文档都会被 `contracts.py --kind emba-import` 拒绝（`OBSERVATION_MISMATCH` / `EVIDENCE_TYPE_MISMATCH`）。Fact 不可变，不存在互升 API；候选状态只能经 §16 的 `validate_transition` 改变。

### 17.2 失败与降级

| 情形 | `status` | 退出码 | 记录 |
|---|---|---|---|
| 全部必需/可选日志解析成功 | `parsed` | 0 | `errors=[]` |
| 缺可选日志（P99/S09/L15/L10/S115） | `partial` | 0 | 每项一条 `MISSING_ARTIFACT` |
| `--require` 指定的日志缺失 | `failed` | 1 | `MISSING_REQUIRED_ARTIFACT`，`requirements.missing` 列出角色 |
| `--require` 含未知角色 | 不产出 | 2 | `BAD_REQUIRE` |
| 存在非空 `emba_error.log` | `partial` | 0 | `EMBA_ERROR_LOG`；对应 `stage` Fact 仍为 `static-discovery` 且 `failure=true` |
| 坏行 / 列数不符 | `partial` 或 `failed` | 0 / 1 | `PARSE_ERROR`，带文件与行号，不静默跳过 |
| 缺 F50 | `failed` | 1 | `F50_MISSING` |
| 版本不符 / 缺版本 | `failed` | 1 | `EMBA_VERSION_MISMATCH` / `EMBA_VERSION_MISSING` |
| `--firmware` 实算哈希不符 | `failed` | 1 | `FIRMWARE_MISMATCH` |

`requirements.satisfied` 表示对应产物**已提供**，不表示其内容解析无误；内容错误仍记 `PARSE_ERROR` 并降级为 `partial`（`--strict` 退出 3）。`--strict` 下 `partial` 退出 **3**；`--status-only` 与 `--strict` 互斥。`status=failed` 的结果**不得导入黑板**（`EMBA_FAILED`）；导入前还会核对 `run_id` 与 `firmware_sha256`（`RUN_MISMATCH` / `FIRMWARE_MISMATCH`）。

### 17.3 确定性

不写生成时间；`observed_at` 取输入文件 mtime（UTC），ID 由 `run_id` 与内容哈希派生，数组按固定键排序，JSON `sort_keys=True`。同一份日志重复解析输出**字节一致**，重复 `board_store.py import --emba` 全部计为 `duplicates`，不改变 `revision`。仓库内 `assets/emba-sample/` 是按 EMBA HEAD `65b7870fb` 日志布局构造的合成夹具，真实产物应替换夹具并用 `--firmware` 核对固件哈希。

### 17.4 真实格式校准

适配器按 EMBA 的实际写入点校准，而不是只按表头猜字段：

| 真实行为 | 源码位置 | 适配器处理 |
|---|---|---|
| F50 每行固定用 8 个 `NA` 补齐尾部列，`system_emulation_state` 的值本身可含 `;`（如 `booted;IP_DET`） | `helpers/helpers_emba_print.sh:333` 的 `write_csv_log()` | 过滤空/NA 单元格后再拼接，数字字段不再被 `;NA…` 污染，状态值保留内部 `;` |
| F50 的 `user_emulation_state` 列实际写的是 `lUSER_EMUL_CNT`（成功用户态仿真的数量），不是状态字符串 | `modules/F50_base_aggregator.sh:252-256` | 输出 `user_emulation_count`（整数）并保留 `user_emulation_state_raw`；`system_booted` 按 token 判定，`IP_DET` 等标志保留原样 |
| L10 的 IP 与网络模式带展示前缀：`IP address: 192.168.0.1`、`Network mode: default (…)` | `modules/L10_system_emulation.sh:3180` | `ip` / `network_mode` 存机器值，`ip_raw` / `network_mode_detail` 保留原始展示文本 |
| L10 的 `available network services` 只列 nmap 判定为 open 的端口；空值表示没有观测到开放端口 | `modules/L10_system_emulation.sh:3180` | 不生成 `trigger=false` 的 `port-response`，只记 limitation；有端口时才落 Fact |
| P99 同时记录 ELF 与 PE32，`class` / `file_output` 都含类型文本 | `modules/P99_prepare_analyzer.sh` | ELF → `elf`；PE32 → `file` + `format=PE32`，不把 Windows 可执行文件冒充 Linux ELF |
| S09 表头第 4 列写作 `version_rule`，实际写入 `lAPP_NAME`；第 8 列表头是 `static/emulation`，实际是类型列 | `modules/S09_firmware_base_version_check.sh:477` | 事实字段命名为 `app_name`，类型列映射到 `mode`，不把产品名误读成版本规则 |
| S115 成功行由 ANSI 颜色码包裹，末尾带英文句号 | `modules/S115_usermode_emulator.sh:891` | 先剥 ANSI 再匹配，去掉路径末尾句号 |
