# 数据契约（FirmwareManifest / AuditTask / Candidate / Finding / Evidence / GateResult / SandboxRun / BenchManifest）

本文件定义跨阶段传递的结构化数据，以及**校验入口、版本规则、兼容模式边界**。目标是消除「同一事实在 plan、报告、gate-config 里三种写法」的漂移：任何下游脚本要消费上游产物时，先看 schema 版本，再按本文件取字段。

配套校验器：`scripts/contracts.py`（纯标准库）。

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
| ID 唯一 | `F-`、`C-`、`E-` 三类 ID 在同一文档内不得重复，跨文档引用必须能对上 |
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

## 8. SandboxRun（`sandbox-run/1.0`）

不可信固件每次执行的留痕。由 `scripts/sandbox_run.py` 产出，动态证据用它证明「命令确实在隔离环境里跑过」。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `sandbox-run/1.0` |
| `mode` | enum | ✅ | `sandbox`（容器）/ `host-opt-in`（显式授权宿主机）/ `check`（只探测）/ `fail-closed`（拒绝执行） |
| `host_fallback` | bool | ✅ | **必须为 false**：隔离不可用只能失败关闭，不得回退宿主机 |
| `command` | array | ✅ | 实际执行的 argv（容器模式含全部隔离参数） |
| `policy` | object | ✅ | 生效的网络/内存/CPU/PID/只读/用户策略 |
| `runtime` | object | — | 运行时名、版本、路径、探测结果 |
| `mounts.firmware` | object | — | `{path, sha256, read_only, target}`；`sha256` 是目录指纹 |
| `exit_code` / `timed_out` | int / bool | — | 命令退出码与超时标志 |
| `stdout_head` / `stderr_head` | string | — | 有界截断的输出摘要 |

退出码：`0` 成功 / `1` 命令失败 / `2` 用法 / `3` 隔离不可用（fail-closed）/ `4` 策略拒绝 / `124` 超时。

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
