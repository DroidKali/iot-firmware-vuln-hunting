# 数据契约（FirmwareManifest / AuditTask / Candidate / Finding / Evidence / GateResult / SandboxRun / BenchManifest / EmbaImport / EmulationPlan / QilingPlan / QilingEvent / QilingImport / SchedulerRules / SchedulerResult / ToolIndex / 黑板对象 / 执行路径）

本文件定义跨阶段传递的结构化数据，以及**校验入口、版本规则、兼容模式边界**。目标是消除「同一事实在 plan、报告、gate-config 里三种写法」的漂移：任何下游脚本要消费上游产物时，先看 schema 版本，再按本文件取字段。

配套校验器：`scripts/contracts.py`（纯标准库）。`--list` 当前列出 24 种 schema；候选的整文件 envelope 由 `candidates` 文档校验器单独处理。

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

报告 ④ 区块的机器可读形态。每条漏洞有 9 个必填字段（与 `references/reporting.md` 一致），缺一即不合格；`candidate_id` 与 `cwe` 是可选追溯/匹配字段，不计入这 9 个必填字段。

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
| `cwe` | string | — | 可选 CWE 编号；接受 `CWE-78` / `cwe_78` / `78`，基准评测统一归一化为 `CWE-78`（见 §9.2） |

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
| `target_sha256` | string | 条件 | 64 hex；命令注入/缓冲区溢出/路径穿越/认证绕过/SSRF/反序列化升级时必需，且必须与候选/policy 一致 |
| `content_sha256` | string | — | 64 hex；冲突与同 ID 不同内容的签名优先使用它 |
| `revoked` / `revoked_at` | bool / string | — | `revoked=true` 必须有 `revoked_at`；已撤销证据不得用于升级 |
| `expires_at` | string | — | ISO 8601；已过期证据不得用于升级 |
| `superseded_by` | string | — | 已被哪条证据取代；非空时不得用于升级 |
| `supersedes` / `contradicts` | array | — | 证据 ID 数组；命中本次同时选中的证据时拒绝 |
| `conflict_group` | string | — | 同组证据的签名必须一致，否则 `EVIDENCE_CONFLICT` |
| `type` | enum | ✅ | `static` / `dynamic` / `emulation` / `fuzzing` / `manual` |
| `observed_at` | string | ✅ | ISO 8601 带时区 |
| `status` | enum | ✅ | `parsed` / `partial` / `failed`；非 `parsed` 必须在 `limitations` 说明缺什么 |
| `source` | object | ✅ | `{type, tool, path?, line?, tool_version?, reliability?}`；`type` 为 `static`/`dynamic`/`emulation`/`tool-report`/`manual`，`tool` 必填；`reliability` ∈ `high`/`medium`/`low`/`unknown` |
| `artifact` | object | — | `{path, sha256, size?}`，原始产物 |
| `raw_log` | object | — | `{path, sha256}`，原始日志 |
| `hook` | object | — | `{mechanism: syscall|api|libc|other, name}`；`system()` 是 libc/api Hook，`execve` 才是 syscall Hook |
| `filter` | object | — | `{rule_id, rule_version}`，事件过滤规则留痕 |
| `event` | object | 动态/仿真必需 | `{type, trigger?: bool, args?: object}`；`trigger` 表示这次观察是否真触发 |
| `supports` | array | — | 判据语义声明；提供时必须是非空数组，每项 `{criterion, kind, details?}`。`criterion` 与 `kind` 必须是非空字符串，`details` 必须是对象；`details.path` / `details.argv` 若出现必须是非空字符串数组 |
| `limitations` | array | 非 `parsed` 必需 | 字符串数组 |

约束：`dynamic` / `emulation` 证据必须带 `event`；`static` 证据必须带 `source.path` 或 `artifact`。这些约束由 `contracts.py --kind evidence` 直接执行，避免「只写一句我跑过了」当证据。

**判据语义绑定（`supports`）**：`evidence_id` 只证明这条证据存在，不证明它支持某个 `required_criterion`。`confirmed` 的 `policy.criterion_evidence` 把判据映射到 Evidence ID 后，校验收紧为「ID 在该判据的语义声明里也必须成立」：

- Evidence 的 `type` 不在该判据允许类型内 → `CONFIRM_CRITERION_TYPE`；
- Evidence 没有 `supports`，或其中没有 `criterion` 等于该判据的条目 → `CONFIRM_CRITERION_UNSUPPORTED`；
- 有条目但 `kind` 不在允许种类、缺必需 `details` 键、`details.path` 少于该判据要求的长度、`sink` 不在白名单、`argv` 不是非空字符串数组、或 `any_of` 无一成立 → `CONFIRM_CRITERION_SEMANTICS`。

`criterion_evidence` 引用一个本轮未选中的 Evidence ID 仍是 `CONFIRM_EVIDENCE_REF_NOT_FOUND`，判据本身没有绑定仍是 `CONFIRM_CRITERION_UNBOUND`；两者与上述语义错误分开报，不能用「证据存在」掩盖「语义不成立」。

同一条 Evidence 可以支持多个判据，但每个判据都必须在 `supports` 中单独给出自己的 `kind` 与 `details`；不禁止共用，禁止的是一条观察被复述成多个不同判据。例如一条动态证据可以同时声明调用链与 sink 执行，但两件事必须分别可核对：

```json
{"evidence_id": "E-EXEC", "type": "dynamic", "supports": [
  {"criterion": "sink_reachable", "kind": "call-path",
   "details": {"path": ["main", "do_ping", "system"]}},
  {"criterion": "command_execution", "kind": "sink-execution",
   "details": {"sink": "system", "argv": ["ping", "-c", "1"]}}
]}
```

`confirmed` 成功时结果新增 `criterion_sources`（判据 → 实际使用的 Evidence ID 列表）与 `shared_evidence`（被两个以上判据引用的 Evidence ID 排序列表）。`shared_evidence` 只做披露，不是拒绝理由；是否成立仍由每个判据各自的 `supports` 条目决定。各漏洞类型的判据矩阵见 §16。

**升级时的额外要求（M6）**：`contracts.py` 仍接受无 schema 的 `evidence/1.0` 历史轻量形态以兼容旧产物，但 `board_transitions.validate_transition` 只接受 `evidence/1.1`；无 schema → `EVIDENCE_SCHEMA_REQUIRED`，其他 schema → `EVIDENCE_SCHEMA_UNSUPPORTED`。因此「能导入黑板」不等于「能用于升级候选」。

## 7. GateResult（`gate-config/1.1`）

`coverage_gate.py --gate-config` 的输出，供 CI 与编排层消费。人类读 `40-coverage.md`，机器读这个文件。

| 字段 | 说明 |
|---|---|
| `schema_version` | `gate-config/1.1` |
| `profile` / `strict` / `gate_version` | 运行配置 |
| `checks` | 每项检查的 `{name, status, detail, required}`，status ∈ `PASS`/`FAIL`/`WARN`/`SKIPPED` |
| `summary` | `{pass, fail, warn, skipped, executed, total, error}` |
| `result` | `pass`/`fail`；仅当无 FAIL、且 strict 下无 required 的 SKIPPED 时为 `pass` |
| `blocked` | **机器可读阻断原因**：`{code, detail}`。code 含 `CHECK_FAILED`、`CHECK_NOT_EXECUTED`、`LAYER1_MISSING`、`LAYER1_CORRUPT`、`LAYER1_NO_INTEGRITY`、`LAYER1_SCHEMA`、`LAYER1_WALK_ERROR`、`LAYER1_ANALYZER_HOST`、`MANIFEST_*`、`STAGE_*`、`CAND_PARSE_ERROR`、`CAND_INPUT_INVALID` |
| `candidate_input` | `{mode, schema, parse_complete, parse_errors, total, reason}`；`mode` ∈ `structured`/`text`/`legacy-text` |
| `scan_integrity` | `{verdict, complete_raw, gaps, unwaived, waived, files_*, walk_errors, engine_verdict, isolation}`；未提供时为 `null` |
| `stages` | 各阶段 `{name, status, required, derived}` |
| `inputs` | 每个输入文件的 sha256，用于证明「这份结论对应这份输入」 |

`WARN` 不参与 `result` 判定，但必须出现在报告里：它表示「降级但可继续」，例如结构引擎不可用而退回正则。

**Layer 1 完整性**：`scan_integrity.gaps` 来自 `partial_files` 与非 scope 类 `skipped_files`；`walk-error`（目录遍历失败）、`read-error`、`stat-failed`、`decode-error`、`too-large` 与 `analyzer-host` 都是硬缺口，未豁免即 `verdict=failed`，分别映射 `LAYER1_WALK_ERROR` / `LAYER1_READ_ERROR` / `LAYER1_ANALYZER_HOST` 等阻断码。`analyzer-host` 由 `engine_status.isolation.host_execution == "explicit-opt-in"` 触发：结构分析器在宿主机解析不可信文件。`scan-waiver/1.0` 可按文件+原因豁免，但仍会出现在报告的 `waived` 中。

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

容器模式**不再向 other 开放写权限**：`--out` 默认 0700。POSIX 非 root 时容器以宿主 `uid:gid` 运行（bind mount 不做 UID 映射，宿主用户可直接写自己的目录）；只有宿主为 root（或 Windows 无 uid 映射）才用 65534，并把 `--out` 临时 `chown` 给该用户，退出后恢复原 mode/uid/gid。Windows 只把权限调整写入 `notes`，不改 ACL。

### 8.1 SandboxPolicy（`sandbox-policy/1.0`）

由 `scripts/resource_manager.py` 校验，**不在 `contracts.py` 的 24 种 schema 内**。策略是运维配置，不是每次运行的产物；其规范化 JSON 的 sha256 写入 `admission.policy_sha256`，用于证明「这次执行用的是哪份策略」。

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

分类：`sandbox-boundary`（固件执行边界，必须经 `sandbox_run.py`）、`sandbox-client`（只调用 `sandbox_run.py` 的适配器）、`host-static-analyzer`（只解析不可信字节、不执行）、`host-tool-probe`（只跑 `--version` / 镜像 inspect，不读固件）、`trusted-metadata`（可信本地元数据）、`test-harness`、`inventory`。出现未知文件即 `unclassified` 并退出 1。当前 22 个脚本共 12 条调用；`sink_scan.py:131` / `sink_scan.py:148` 的 ast-grep / semgrep 仍是 `host-static-analyzer`，是已知残留风险（只解析、不执行）。

## 9. BenchManifest / BenchResult（`bench-manifest/1.0` / `bench-result/1.0`）

检测质量评估的输入与输出，由 `scripts/bench_eval.py` 消费与产出。

**BenchManifest**：`dataset`（名称、版本、kind、license、`real_firmware`、`curation`）、`splits`（`dev` / `holdout`）、`samples[]`（`id` / `path` / `sha256` / `size` / `files[]` 每个文件的哈希 / `arch` / `kind` / `vendor` / `model` / `hardware` / `firmware_version` / `filesystem` / `source` / `acquired_at` / `authorization` / `distribution` / `unpack` / `negative_evidence` / `labels[]`）。每条 label 带 `id`、`category`、`file`、`line`、`cwe`、`symbol`、`review`（`reviewed` / `pending` 等）、`basis`、`labeler`、`reviewer`、`reviewed_at`；`pending` 标签不参与计分。

### 9.1 真实基准门禁（`--require-real`）

`evaluate` 与 `validate` 都接受 `--require-real`。它把「真实基准」从愿望变成逐样本门禁，缺项直接校验失败（退出 **1**），合成集仍可用于契约回归，但不能冒充真实检测质量。

| 对象 | 要求 |
|---|---|
| `dataset` | `kind` 必须为 `real`；`real_firmware` 非空且不得是 `pending` / `unknown` / `tbd` / `none` / `n/a` 等占位值；`curation` 是对象，`custodian`、`review_process` 非空，`reviewed_at` 可选但须为 ISO 日期 |
| 样本标识 | `vendor`、`model`、`hardware`、`firmware_version`、`filesystem` 均为非空字符串 |
| 来源 | `source` 是 `http` / `https` URL；`acquired_at` 是 ISO 日期（`YYYY-MM-DD`）；`authorization` 非空 |
| 分发 | `distribution` 是对象，`allowed` 必须是布尔值，`terms` 非空 |
| 解包 | `unpack` 是对象，`method` 非空，`rootfs` 非空且相对样本目录存在；`key_files` 是非空数组，每项为不含 `..` 的相对路径，必须同时出现在 `files[]` 中且磁盘上真实存在 |
| 负样本 | `kind` 为 `safe` 或 `hard-negative` 时，`negative_evidence` 非空 |
| 标签 | 每条 label 的 `basis`、`labeler` 非空；`review=reviewed` 时还必须有非空 `reviewer` 与 ISO 日期 `reviewed_at`，且 `reviewer != labeler` |
| 集合覆盖 | 样本必须同时包含 `vuln`、`safe`、`hard-negative` 三类；每个 `vuln` 样本至少有一个 `reviewed` 标签 |

满足门禁后，结果顶层 `synthetic=false`，`metrics` 增加 `by_filesystem` 与 `by_vendor` 两个分组。这些字段都是**自报元数据**，不是第三方鉴证：门禁只能阻止缺项进入正式基准、便于复核，不能证明固件来源或授权真实。

### 9.2 CWE 归一化与三阶段匹配

Finding 与 Label 的 `cwe` 都接受 `CWE-78`、`cwe_78`、`78` 等写法，比较前统一规范化为 `CWE-78`；`0`、超过五位或无法识别的值归一化为空串。匹配策略固定为 `same-or-ancestor-descendant`：CWE 相等，或两侧已登记的祖先/后代关系（双向兼容）。未登记的编号只做相等，不猜关系。

同一条 label 与 finding 的判定分三步，前一步不通过就没有后一步：

| 阶段 | 通过条件 |
|---|---|
| 位置 | `sample` 与 `file` 相同，且 `label.line > 0`、`finding.lines` 非空时最小行距 ≤ 3 |
| 类型 | 规范化 `category` 相等或任一侧为 `unknown`；且 CWE 相等或已登记父子关系 |
| 证据 | `symbol` 规范化后相等，或 label 的 `symbol` 出现在 finding 的 `pattern` / `text` 中 |

`matched = type_ok and (location_ok or evidence_ok)`：类型必须通过，定位与符号/文本证据至少一项通过。任一侧缺 CWE 或类别时，按剩余维度判定并标记 `missing`；`missing` 表示「未验证等价」，不能当作已证相等。

分配是一对一的：一个 finding 最多贡献一个 TP，一条 label 最多贡献一个 TP。已被占用的候选不会再把另一条 label 计成 TP，重复命中进入 `details.duplicate_reviewed_matches`，**不计 FP**。FN 的 `reason` 由 `explain_unmatched` 生成，区分「同文件无候选」「候选已被其他标签占用」「候选类型不兼容」「类型通过但定位与证据均不足」四种情况，不做笼统归因。

结果顶层 `matching` 记录本次策略与实际判定。`decisions` 是 `detail_block`：`{count, limit, truncated, items[]}`，`items` 逐项给出 `label_id` / `sample_id` / `finding_index` / `file` / 行号 / 类别 / CWE / `line_distance` / 各阶段布尔值 / `matched` / `reason`，不是按 label ID 直接映射的单个对象。

```json
{"matching": {
  "policy": {"location": "同一文件，行号相差不超过 3",
             "type": "规范化类别相等；CWE 相等或已登记父子关系",
             "evidence": "符号名相等，或标签符号出现在 finding 证据文本中",
             "accept": "类型通过，且定位或证据至少一项通过",
             "category_policy": "normalized-category-equal",
             "cwe_policy": "same-or-ancestor-descendant",
             "assignment": "按定位/符号/行差/索引确定性排序，一 finding 最多一个 TP",
             "missing": "CWE 或类别缺失时按剩余维度匹配，并标记 missing，不视为已验证等价"},
  "stats": {"pairs": 42, "matched": 17,
            "rejected_by_type": 19, "rejected_by_location_evidence": 6},
  "decisions": {"count": 42, "limit": 200, "truncated": false,
    "items": [{"label_id": "L-001", "sample_id": "S-01", "finding_index": 3,
               "file": "bin/httpd", "label_line": 42, "finding_line": 40,
               "label_category": "command-injection", "finding_category": "command-injection",
               "label_cwe": "CWE-78", "finding_cwe": "CWE-78", "line_distance": 2,
               "location_ok": true, "symbol_ok": false, "text_ok": true,
               "evidence_ok": true, "category_ok": true, "category_relation": "same",
               "cwe_ok": true, "cwe_relation": "same", "type_ok": true,
               "matched": true, "reason": "匹配通过：定位+证据；类型通过"}]}}
```

### 9.3 BenchResult

`BenchResult`：`schema` / `tool` / `status` / `synthetic` / `generated_at`、`dataset`、`parameters`、`validation`（`status` / `warnings`）、`scope`（`split`、`samples`、`samples_by_split`、`findings_in_scope`、`findings_total`、`labels_total`、`labels_reviewed`、`labels_not_evaluable`）、`confusion_matrix`（`tp`/`fp`/`fn`/`tn`）、`metrics`（`micro` / `macro` / `by_category` / `by_arch` / `by_split` / `by_filesystem` / `by_vendor`，每项含 precision/recall/F1/FPR/FNR）、`matching`（上节）、`provisional`（`authoritative=false`、`reason`、`labels_included`、`metrics`；标签未复核或存在 `not_evaluable` 样本时必须给出）、`not_evaluable`、`out_of_scope`、`details`（`true_positives` / `false_negatives` / `false_positives` / `unmatched_vulnerable_findings` / `duplicate_reviewed_matches` / `not_evaluable`）、`baseline`、`exit_code`。**不存在顶层 `split` / `counts` / `micro`**——split 在 `scope.split`，计数在 `confusion_matrix`，指标在 `metrics.micro`。

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
| `prev_hash` | string | — | 前一条事件的 `hash`；链首为 `""`，成链后必填 |
| `hash` | string | — | 本事件哈希，64 位小写 hex；随 `prev_hash` 一起出现 |

| `type` | `payload` 必填 |
|---|---|
| `BOARD_INITIALIZED` | `firmware_sha256`；`manifest_id` 可选 |
| `FACT_RECORDED` | `fact`（完整 `fact/1.0` 对象） |
| `CANDIDATE_RECORDED` | `candidate`（完整候选对象） |
| `EVIDENCE_RECORDED` | `evidence`（完整 `evidence/1.1` 对象） |
| `INTENT_CREATED` | `intent`（完整 `intent/1.1` 对象；兼容 `intent/1.0`） |
| `HINT_RECORDED` | `hint`（完整 `hint/1.0` 对象） |
| `EMULATION_RECORDED` | `result`（完整 `emulation-result/1.0` 对象） |
| `CANDIDATE_TRANSITIONED` | `candidate_id` / `from_state` / `to_state` / `reason` / `evidence_refs`；`policy` 可选 |
| `INTENT_STATUS_CHANGED` | `intent_id` / `from_status` / `to_status`；`worker` / `attempts` / `lease` / `outcome` / `result_refs` / `last_failure` / `reason` 可选 |
| `INTENT_LEASE_RENEWED` | `intent_id` / `worker` / `lease`；`previous_expires_at` 可选 |
| `INTENT_COMPLETED_WITH_RESULTS` | `intent_id` / `worker` / `result`（完整 `scheduler-result/1.0`）；`attempt` 可选 |
| `PHASE_ADVANCED` | `from_phase` / `to_phase` / `reason` / `evidence_refs`；`advanced_by` 可选 |
| `BACKTRACK` | `from_phase` / `to_phase` / `reason` / `evidence_refs`；`approved_by` 可选 |

语义与失败模式：

- 只追加：每条事件一行，写入后 `flush` + `fsync` 文件，并对父目录 `fsync`（Windows 跳过目录 fsync）。重复 `dedupe_key` 返回 `duplicate=true` 且不再落盘；回放时同样跳过并计数。
- **跨进程事务**（`board_store.py` 1.1）：所有写操作先抢 `audit.lock`（Windows `msvcrt.locking` / POSIX `fcntl.flock`，默认 10 秒超时，超时报 `LOCK_TIMEOUT`）。锁内重新加载事件日志，再执行去重、`seq` 分配、`apply_event`、追加事件与原子快照；`append(prepare=)` 的 `prepare(state)` 在锁内用最新状态构造载荷，因此 `set_intent_status(expected_status=...)` 是 CAS，`transition` / `backtrack` / `advance_phase` 也都在同一事务里重新取当前状态。进程崩溃时由 OS 释放锁；锁只保护同一工作区，不提供跨机器互斥。
- `seq` 必须从 1 连续；`event_id` 唯一；同一日志出现多个 `run_id` 即 `RUN_MISMATCH`。
- 空行可以容忍（计入 `blank`）。**中间非法 JSON 行**必须报 `PARSE_ERROR` 并非零退出，不得静默跳过；只有最后一行「没有换行且 JSON 不完整」才记为 `truncated_tail`，读取时跳过。`append_event` 遇中间损坏抛 `LOG_CORRUPT` 且不追加；遇 torn tail 先把该尾段隔离到 `<events>.torn-<UTC>`（重名加 `-N`），截断后再追加，不把半行留在真相源里。
- 快照的 `revision` / `event_count` / `last_event_id` 与日志不一致时，`load` 会重建并标记 `recovered=true`；快照缺失也能从日志恢复。
- 重复初始化报 `ALREADY_INITIALIZED`（除非显式 `--force`）；`BACKTRACK` 的 `from_phase` 不是当前阶段报 `PHASE_MISMATCH`，方向不是回退报 `NOT_A_BACKTRACK`。
- `INTENT_STATUS_CHANGED` 的 `worker` / `attempts` / `outcome` / `result_refs` / `last_failure` 全部校验通过后才写入 `intent.status`；否则事件声称切换了状态，重放却停在旧状态。`claimed` 的 `attempts` 必须等于旧值加一，跳号或重放报 `ATTEMPT_MISMATCH`；`done` 必须带成功类 `outcome`，`failed` 必须带失败类 `outcome` 与 `last_failure`（`OUTCOME_REQUIRED` / `FAILURE_REQUIRED`）；`result_refs` 指向的对象必须已在黑板，否则 `RESULT_REF_NOT_FOUND`；重试回到 `open` 时本轮结果引用**追加**到 `result_refs`，不能覆盖上一轮，否则失败尝试的 Evidence/Fact 会脱离 Intent、审计链断裂。转到 `claimed` 时同时写入 `lease`（`payload.lease` 为对象时复制）；`done` / `failed` / `cancelled` 与回到 `open` 都清除 `lease`，`open` 还把 `worker` 置空。
- `INTENT_LEASE_RENEWED` 只在 Intent 为 `claimed` 时合法（否则 `STATE_MISMATCH`），`payload.worker` 必须等于当前持有者（否则 `WORKER_MISMATCH`）；`lease` 必须含 `worker` / `acquired_at` / `heartbeat_at` / `expires_at` 非空字符串与不小于 1 的 `ttl_seconds`，`lease.worker` 与事件 `worker`、`intent.worker` 一致，校验通过后整份替换 `intent.lease`。`previous_expires_at` 只作审计记录，不参与状态判定。
- `INTENT_COMPLETED_WITH_RESULTS` 是**结果回写的唯一原子入口**：`result` 必须是完整 `scheduler-result/1.0`，且 `result.intent_id` / `run_id` / `firmware_sha256` 与黑板一致。事件在一次 `apply_event` 中校验 worker / `attempt`、结果内 ID 重复与黑板冲突、`fact.evidence_refs` 是否悬空，然后**同时**插入 Evidence / Fact、累加 `result_refs` 并更新 Intent 状态；任一项失败整笔拒绝，不落半份证据（`DUPLICATE_ID` / `ID_CONFLICT` / `DANGLING_EVIDENCE` / `ATTEMPT_MISMATCH`）。成功类结果转 `done`，可重试失败在 `max_retries` 内回 `open`，否则转 `failed`。
- `PHASE_ADVANCED` 的 `from_phase` 必须等于当前阶段（`PHASE_MISMATCH`），`to_phase` 必须是下一阶段（`NOT_AN_ADVANCE`），`reason` 非空（`REASON_REQUIRED`），`evidence_refs` 必须存在（`EVIDENCE_REF_INVALID` / `EVIDENCE_REF_NOT_FOUND`）。前进用 `PHASE_ADVANCED`，回退只能用 `BACKTRACK`，不能用前进事件倒着写。
- 事件载荷内的对象若 `run_id` 与事件不一致，报 `RUN_MISMATCH`；引用不存在的证据 / 来源 / Intent，报 `DANGLING_EVIDENCE` / `DANGLING_REF`。
- 回放遇到状态的 `from_state` 与快照当前状态不一致，报 `STATE_MISMATCH`；未知事件类型报 `UNKNOWN_EVENT`。

**事件哈希链（可选）**：事件可带 `prev_hash` / `hash`，用于发现日志被改写或拼接；没有这两个字段的旧日志仍可读。

```text
hash = sha256("board-event-hash/1.0\n" + canonical_json(去掉 hash 字段的事件))
```

`canonical_json` 使用键排序、紧凑分隔与不转义的非 ASCII 文本。链首 `prev_hash=""`；之后每条 `prev_hash` 等于前一条的 `hash`。若前一条没有 `hash`，`board_store` 追加时保持无链，不会凭空起链。因此旧日志要么完全无链（`hash_chain=absent`），要么是开头无 hash、之后才起链的 legacy 前缀（`legacy-prefix`）。`verify` 的 `hash_chain` 取 `absent` / `legacy-prefix` / `complete`，并给出 `last_hash`；成链后缺字段报 `HASH_CHAIN_PARTIAL`，链首 `prev_hash` 非空或后续不指向前一条报 `HASH_CHAIN_BROKEN`，重算不符报 `HASH_MISMATCH`，格式不是 64 位小写 hex 报 `HASH_INVALID`。

`truncated_tail` 不是哈希错误，也不计入 `errors`：`verify` 只报告它，退出码仍由 `errors` 决定；下一次 append 会先隔离再修复。报告同时给出 `ok`、`events`、`duplicates`、`last_seq`、`blank`、`hash_chain`、`last_hash` 与 `truncated_tail`。

```bash
python scripts/board_events.py verify --events work/audit-events.jsonl --json work/audit-events-report.json
```

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

## 14. Intent（`intent/1.1`，兼容 `intent/1.0`）与 Hint（`hint/1.0`）

Intent 是**尚未执行的方向**：必须由已有事实/候选/证据/Intent 触发，带唯一去重键与预算。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `intent/1.1`；`intent/1.0` 仅作历史兼容，不参与 M7 调度
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
| `timeout_seconds` / `max_retries` | int | — | 分别 ≥1 / ≥0（规则模板里 `max_retries` ≤10） |
| `priority` | int | — | 0..100；调度按数值降序，Hint 最多加 15 分，不能绕过门禁 |
| `depends_on` | array | — | 依赖的 Intent ID；依赖失败/取消/缺失时本 Intent 不得 READY |
| `attempts` | int | 条件 | 第几次尝试；`claimed` 的 `intent/1.1` 必须 ≥1 |
| `outcome` | enum | 条件 | `success` / `partial` / `failed` / `blocked` / `not_applicable` / `timed_out` / `cancelled` |
| `result_refs` | array | — | 所有尝试累积的 Evidence / Fact ID（重试追加，不覆盖）；必须已存在于黑板 |
| `last_failure` | object | 条件 | `{code, message, category?, retryable?, at?}`；`failed` 必填 |
| `preconditions` / `stop_conditions` / `expected_outputs` | array | — | 字符串数组；`stop_conditions` 是执行者必须遵守的停止判据，不是装饰 |
| `worker` | string/null | — | 认领者 |
| `claimed_at` / `concluded_at` | string | 条件 | `claimed` 必须有 `worker`+`claimed_at`；`done`/`failed`/`cancelled` 必须有 `concluded_at` |
| `lease` | object | 条件 | 租约；`worker` / `acquired_at` / `heartbeat_at` / `expires_at` 为非空字符串，`ttl_seconds` 为 ≥1 整数；`lease.worker` 必须等于 `worker`；仅 `claimed` 时存在 |

Intent 状态机：`open → claimed | cancelled`；`claimed → done | failed | cancelled | open`（释放）；`done` / `failed` / `cancelled` 为终态。认领必须带 `worker`，否则 `MISSING_WORKER`；非法转换报 `ILLEGAL_TRANSITION`。

`intent/1.1` 额外约束：`claimed` 必须带 `attempts>=1`；`failed` 必须带 `last_failure` 且 `outcome∈{failed,blocked,timed_out}`；`done` 必须带 `outcome∈{success,partial,not_applicable}`。`partial` 不能被折叠成 `success`，`timed_out` / `blocked` 也不能被写成「没有发现」。失败重试由 `max_retries` 与 `attempts` 共同决定，超出上限即 `failed`，不得无限重试。

**租约（`lease`）**：`claim` 在写入 `claimed` 的同一事务里写入 `lease`。`acquired_at` / `heartbeat_at` 取领取时刻，`expires_at = 当前时间 + ttl_seconds`；`ttl_seconds` 默认 900，允许 1..86400，越界报 `LEASE_INVALID`。`heartbeat` 只有当前持有者能续租：Intent 非 `claimed` 时报 `INTENT_NOT_CLAIMED`，`worker` 与当前持有者不一致时报 `WORKER_MISMATCH`；续租重新计算 `expires_at` 与 `heartbeat_at`，`previous_expires_at` 只作审计。

- 清除时机：`done` / `failed` / `cancelled` 与回到 `open` 都删除 `lease`；回到 `open` 同时清空 `worker`，下一次认领重新计时并令 `attempts+1`。
- `LEASE_EXPIRED`：`complete` 时 Intent 仍是 `claimed` 但租约已过期，拒绝回写，Intent 保持 `claimed`，不会因一次迟到结果自动转 `open` 或 `done`。
- `WORKER_MISMATCH`：非持有者发 `heartbeat`，或回写结果的 `worker` 与当前持有者不一致。
- `reclaim` 把过期 `claimed` 转回 `open`，`reason=lease_expired`，保留 `attempts` 与既有 `result_refs`，不删除任何 Evidence / Fact；旧式没有 `lease` 的 `claimed` 不视为过期，不能被 `reclaim` 回收。

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
| `phase` | enum | — | `P0`…`P5`；默认 `P0`，只能由 `PHASE_ADVANCED` / `BACKTRACK` 改变 |
| `manifest_id` / `last_event_id` | string | — | 清单与最后事件 |
| `evidence` / `facts` / `candidates` / `intents` / `hints` / `emulation_results` / `backtracks` | array | ✅ | 七类数组；每项走对应 validator |
| `counters` | object | — | 若提供，必须与各数组实际长度一致 |

交叉引用（悬空即 `DANGLING_REF`）：`fact.evidence_refs` 必须指向 `evidence`；`intent.from` 必须指向 facts / candidates / evidence / intents；`emulation_result.intent_id` 必须指向 `intents`；`emulation_result.evidence_refs` 与 `backtrack.evidence_refs` 必须指向 `evidence`。每类 ID 在各自数组内唯一。

**PHASE_ADVANCED** 记录：`{from_phase, to_phase, reason, evidence_refs, advanced_by?}`。`from_phase` 必须等于黑板当前 `phase`；`to_phase` 必须是下一阶段，否则 `NOT_AN_ADVANCE`；`reason` 非空；`evidence_refs` 必须指向已存在的证据。阶段前进事件不能代替 `BACKTRACK`，也不能用来跳过门禁：它只记录流程状态，不放宽任何检查。

**BACKTRACK** 记录：`{from_phase, to_phase, reason, evidence_refs, approved_by?}`。`from_phase` 必须等于黑板当前 `phase`，且 `to_phase` 必须是更早的阶段，否则 `PHASE_MISMATCH` / `NOT_A_BACKTRACK`。回退必须带触发证据；没有证据的「感觉不对」不能改阶段。

候选状态转换白名单（`board-transitions/1.1`）：

| 当前状态 | 允许转到 |
|---|---|
| `hypothesis` | `pending_static_analysis` / `not_applicable` / `blocked_by_environment` |
| `pending_static_analysis` | `pending_dynamic_validation` / `validated` / `not_found` / `not_reproduced` / `not_applicable` / `blocked_by_environment` |
| `pending_dynamic_validation` | `validated` / `confirmed` / `not_reproduced` / `blocked_by_environment` / `not_applicable` |
| `validated` | `confirmed` / `not_reproduced` / `blocked_by_environment` |
| `blocked_by_environment` | `pending_static_analysis` / `pending_dynamic_validation` / `not_applicable` |

终态：`confirmed` / `not_found` / `not_reproduced` / `not_applicable`。`VERIFIED` 是 `confirmed` 的别名（持久化只写小写状态）；同状态转换报 `SAME_STATE`，终态再转报 `TERMINAL_STATE`。

进入 `validated` 或 `confirmed` 时，`validate_transition` 按候选的漏洞类型（`policy.vuln_type`）检查证据绑定与判据。M6 起，以下规则是**硬前置**，任一不满足即拒绝升级：

- 候选必须自带合法 `run_id` 与 `firmware_sha256`；缺 run → `CANDIDATE_RUN_ID_MISSING`，run 非法 → `CANDIDATE_RUN_ID_INVALID`，缺固件 → `CANDIDATE_FIRMWARE_MISSING`，固件非法 → `CANDIDATE_FIRMWARE_INVALID`。命令行 `--run-id` / `--firmware-sha256` 只做交叉校验，不一致 → `RUN_ID_MISMATCH` / `FIRMWARE_MISMATCH`。
- `contracts.validate_evidence` 必须可导入；导入失败、抛异常或返回非数组 → `CONTRACT_UNAVAILABLE` / `EVIDENCE_VALIDATOR_ERROR`（fail-closed，不得跳过）。
- 每条证据必须声明 `evidence/1.1`；缺 schema → `EVIDENCE_SCHEMA_REQUIRED`，其他 schema → `EVIDENCE_SCHEMA_UNSUPPORTED`，结构不合法 → `EVIDENCE_INVALID`。
- 所有证据必须同 run、同固件；跨 run → `EVIDENCE_NOT_BOUND_TO_RUN`，固件缺失/非法/不一致 → `EVIDENCE_FIRMWARE_MISSING` / `EVIDENCE_FIRMWARE_INVALID` / `FIRMWARE_MISMATCH`。
- 漏洞类型要求目标绑定时，候选/policy 必须给出 `target_sha256`，且每条证据都必须带目标哈希并一致；缺失 → `TARGET_HASH_REQUIRED`，非法 → `TARGET_HASH_INVALID`，冲突 → `TARGET_HASH_MISMATCH`。
- 证据生命周期：`revoked=true` → `EVIDENCE_REVOKED`；`superseded_by` 非空 → `EVIDENCE_SUPERSEDED`；`expires_at` 非法/已过期 → `EVIDENCE_EXPIRY_INVALID` / `EVIDENCE_EXPIRED`；`status=failed` → `EVIDENCE_FAILED`；同 `evidence_id` 不同内容 → `EVIDENCE_ID_CONFLICT`；`supersedes` / `contradicts` 命中本次选中证据 → `EVIDENCE_SUPERSEDES_CONFLICT` / `EVIDENCE_CONTRADICTION`；同 `conflict_group` 签名不一致 → `EVIDENCE_CONFLICT`。
- 至少一条证据的 `type` 属于该漏洞类型允许的来源；否则 `EVIDENCE_TYPE_NOT_ACCEPTED`。`validated` 用完整 `evidence_types`（可含静态/人工）；`confirmed` **只**用下表 `confirm_evidence_types`，纯静态线索不能成为最终结论。
- `confirmed` 的运行时证据要求：

  | 漏洞类型 | 可接受的确认证据 |
  |---|---|
  | `command-injection` / `path-traversal` / `auth-bypass` / `ssrf` / `deserialization` | `dynamic` / `emulation` |
  | `buffer-overflow` | `dynamic` / `emulation` / `fuzzing` |
  | `hardcoded-credential` | `static` / `manual` |
  | `other` | `dynamic` / `emulation` / `manual` |

  没有一条命中 → `CONFIRM_EVIDENCE_REQUIRED`。
- `policy.criteria` 必须覆盖该类型的 `required_criteria` 且全为 true；缺失 → `VALIDATION_CRITERIA_NOT_MET`。`confirmed` 还必须提供 `policy.criterion_evidence`：对象，每个 `required_criteria` 对应非空 Evidence ID 字符串（或字符串数组），且这些 ID 必须在本轮选中的证据里；缺对象 → `CONFIRM_CRITERIA_EVIDENCE_REQUIRED`，判据未绑定 → `CONFIRM_CRITERION_UNBOUND`，值非法 → `CONFIRM_EVIDENCE_REF_INVALID`，引用不在本轮证据 → `CONFIRM_EVIDENCE_REF_NOT_FOUND`。每条引用的证据还必须通过该判据的语义检查（`supports`，见 §6.1）：类型不符 → `CONFIRM_CRITERION_TYPE`，缺 `supports` 或缺该 `criterion` 条目 → `CONFIRM_CRITERION_UNSUPPORTED`，`kind` / 必填 `details` / `path` 长度 / `sink` / `argv` / `any_of` 不符 → `CONFIRM_CRITERION_SEMANTICS`。成功结果带 `criterion_sources` 与 `shared_evidence`；同一 Evidence 支持多个判据时，每个判据都要有自己的 `supports` 条目。
- 需要触发上下文的类型（命令注入、缓冲区溢出、路径穿越、认证绕过、SSRF、反序列化）必须有 `event.trigger=true` 或匹配的触发事件；`validated` 还可由候选自带 `trigger` / `poc` / `poc_path` 兜底，**`confirmed` 不接受候选自证**，否则 `MISSING_TRIGGER_CONTEXT`。
- `policy.expected` 与 `policy.actual` 要么都给且相等，要么都不给；只给一方 → `EXPECTED_ACTUAL_NOT_SUPPORTED`。
- 其余失败码：`BAD_CANDIDATE` / `BAD_STATE` / `ILLEGAL_TRANSITION` / `TYPE_RULE_MISSING` / `CANDIDATE_TYPE_MISMATCH` / `EVIDENCE_REQUIRED` / `EVIDENCE_INVALID`；成功为 `OK`。

**判据语义矩阵（`CRITERION_SUPPORT`）**：`supports[].kind` 必须命中下表允许种类，`details` 必须包含「必需键」；`path` 类数组还要求长度为 `min_path`（默认 2）且元素为非空字符串。允许的 Evidence 类型见末列。

| 漏洞类型 | `criterion` → `kind` / 必需 `details` | 允许的 Evidence `type` |
|---|---|---|
| `command-injection` | `sink_reachable` → `call-path` / `path`（≥2）；`user_controlled_input` → `input-origin` / `origin`、`field`；`command_execution` → `sink-execution` / `sink`、`argv`，`sink` ∈ `execve`/`system`/`popen`/`posix_spawn` | 前者 `static`/`dynamic`/`emulation`；后两者 `dynamic`/`emulation`/`fuzzing` |
| `buffer-overflow` | `input_length_unbounded` → `input-length` / `length`；`memory_write` → `memory-write` / `address`；`crash_or_control` → `crash` 或 `control` / `any_of` 中至少一个：`signal`、`pc`、`control` | `dynamic`/`emulation`/`fuzzing` |
| `path-traversal` | `user_controlled_path` → `path-input` / `path`（≥2）、`origin`；`traversal_reaches_file` → `path-traversal` / `requested`、`resolved`；`file_access` → `file-access` / `path` | 前者 `static`/`dynamic`/`emulation`；后两者 `dynamic`/`emulation` |
| `hardcoded-credential` | `credential_present` → `credential` / `location`、`value_sha256`；`credential_effective` → `credential-effective` / `mechanism`；`not_placeholder` → `credential-quality` / `reason` | 前两者 `static`/`manual`（`credential_effective` 另接受 `dynamic`/`emulation`）；后者 `static`/`manual` |
| `auth-bypass` | `protected_endpoint_reachable` → `endpoint` / `endpoint`；`check_bypassed` → `auth-bypass` / `expected`、`observed`；`unauthorized_access` → `unauthorized-access` / `resource` | 前者 `static`/`dynamic`/`emulation`；后两者 `dynamic`/`emulation` |
| `ssrf` | `url_controlled` → `input-origin` / `origin`、`field`；`request_issued` → `request` / `target`；`target_reachable` → `connect` / `target` | 前者 `static`/`dynamic`/`emulation`；后两者 `dynamic`/`emulation` |
| `deserialization` | `untrusted_data_reaches_parser` → `parser-input` / `parser`、`origin`；`gadget_or_type_confusion` → `gadget` / `gadget`；`code_execution` → `sink-execution` / `sink`，`sink` ∈ `execve`/`dlopen`/`malloc` | 前者 `static`/`dynamic`/`emulation`；后两者 `dynamic`/`emulation` |
| `other` | `evidence_supports_claim` → `claim` / `claim`；`scope_matched` → `scope` / `scope` | `static`/`dynamic`/`emulation`/`fuzzing`/`manual` |

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

## 18. EmulationPlan（`emulation-plan/1.0`）与执行边界

`emu_plan.py` 只读探测 rootfs / 内核 / init 并输出启动计划；它**不启动 QEMU、不执行固件字节、不自动构建镜像**。`emu_run.py` 消费该计划，只有 `status=ready`、契约通过且内核/镜像哈希复核通过时才经 `sandbox_run.py` 执行。

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` / `plan_id` | string | ✅ | `emulation-plan/1.0`；`plan_id=PLAN-*`，由 rootfs 指纹、内核哈希、镜像路径、架构、init 与 argv 派生，重复探测应稳定 |
| `tool` / `version` | string | ✅ | 生成器与版本 |
| `status` | enum | ✅ | `ready` / `blocked`；`ready` 必须无 blockers 且有 kernel 与 image，`blocked` 必须 blockers 非空 |
| `run_id` / `intent_id` / `firmware_sha256` | string | — | 计划可先不绑定；执行时必须有，缺失即 `RUN_ID_MISSING` / `INTENT_ID_MISSING` / `FIRMWARE_SHA_MISSING` |
| `firmware_root` | string | ✅ | 容器内 `:ro` 挂载的根；内核与镜像必须位于其下，否则 `KERNEL_OUTSIDE_MOUNT` / `IMAGE_OUTSIDE_MOUNT` |
| `rootfs` | object | ✅ | `{path, kind: directory / image, sha256, files, bytes, arch, bits, endian, abi, interpreter, libc, selected_init, init_source, init_candidates, inittab, evidence}` |
| `kernel` | object/null | — | `{path, mount_path, sha256, format, size}`；无内核时 `null` 并产生 `KERNEL_MISSING` |
| `image` | object/null | — | `{path, mount_path, exists, sha256, size, fs}`；`fs` 必须识别为 ext2；尚未构建时存在性与哈希为 null |
| `build` | object/null | — | `{required, size_mb, commands}`；`commands` 是待执行的 `truncate` / `mke2fs -d` / `e2fsck` 命令，计划本身不执行 |
| `qemu` | object | ✅ | `{binary, path, available, version, machine, cpu, kernel_format, console, root_device, disk_bus, argv, cmdline, sandbox_cmd, mounts}`；`argv` 使用容器内路径（`/firmware/...`、`/out/serial.log`） |
| `network` | object | ✅ | `{mode: none / user, hostfwd, guest_ip, host_forward_reachable, notes}`；默认 `none` |
| `budget` | object | ✅ | `{timeout_s, memory, cpus, attempts}` |
| `blockers` / `warnings` / `limitations` | array | ✅ | blocker 为 `{code, message, next_action}`；warnings/limitations 为字符串数组 |

**blocker 码**：`ROOTFS_EMPTY`、`ARCH_UNKNOWN`、`ARCH_UNSUPPORTED`、`KERNEL_MISSING`、`KERNEL_OUTSIDE_MOUNT`、`KERNEL_ARCH_MISMATCH`、`IMAGE_OUTSIDE_MOUNT`、`QEMU_MISSING`（仅 `--require-qemu` 时阻断；默认只告警）。每个 blocker 必须给出 `next_action`，不能只写「失败」。

### 18.1 执行边界

- **先复核再启动**：`emu_run.py` 校验计划 schema 与契约、`run_id` / `intent_id` / 固件哈希、镜像是否为 ext2 且 sha256 匹配、内核 sha256 匹配、`firmware_root` 存在；任一失败写 `BLOCKED` 结果并以 **退出 3** 结束，绝不启动沙箱。
- **固定沙箱**：执行命令固定包含 `--mode sandbox`，没有宿主机回退；容器内 QEMU 的固件挂载只读、串口写 `/out/serial.log`，网络默认 `none`。资源策略、槽位与预算由 `sandbox_run.py` / `resource_manager.py` 决定，`emu_run.py` 不能放宽。
- **`--check` 不执行**：只做计划复核；不需要 `--out`，不写 EmulationResult，不启动 QEMU。
- **退出码**：`0` SUCCESS、`1` FAILED/PARTIAL、`2` 用法、`3` 计划阻断或 BLOCKED、`4` 策略拒绝、`5` 资源准入拒绝、`124` 超时。
- **观察不升级**：`observations[].type` 只能是 `emulation`；`evidence_refs` 初始为空，不生成 finding。`SUCCESS` 只表示「启动到 console 标记」，既不是漏洞，也不能直接让候选进入 `validated` / `confirmed`。
- **失败分类**：`rootfs-mount` / `no-init` / `init-crash` / `library-missing` / `illegal-instruction` / `kernel-panic` / `kernel-format` / `boot-no-output` / `backend-unavailable` / `timeout` / `plan-blocked` / `policy-rejected` / `admission-rejected`。`FAILED` / `BLOCKED` / `TIMED_OUT` 必须带 `failure{category, reason, retryable}`，`PARTIAL` 必须带非空 `limitations`。

### 18.2 已记录的一次真实运行

仓库内保留了一份真实运行证据，用于说明本契约不是只在假 sandbox 上跑过：

- 输入：Hak5 WiFi Pineapple Nano 的 OpenWrt 19.07.2 rootfs（1,965 个普通文件），ext2 镜像 168 MiB，sha256 `694b7fb8...`；
- 成功路径：`PLAN-e23e2aa53de7` → `EMU-7b2e141b296c`，`status=SUCCESS`，30 秒窗口，串口第 177 行 `/ #`，观察 `shell-prompt`；使用 OpenWrt Malta 通用内核（非厂商 ath79 内核）；
- 失败路径：厂商 raw 内核 → `EMU-01c2df7e12c6`，`status=FAILED`，`failure.category=kernel-format`，`retryable=false`；QEMU 报 `The image is not ELF`；
- 产物与哈希：`assets/qemu/real-run-malta/`，含计划、结果、沙箱报告、串口与 `README.md`。

该记录只支持「真实 rootfs 用户态启动到 shell」；不证明完整固件、厂商原机行为、网络/服务或漏洞成立。

## 19. QilingPlan / QilingEvent / QilingImport（`qiling-*/1.0`）与定向仿真边界

Qiling 分支用于「目标二进制明确、依赖可构建、可用受控输入定向验证」的用户态执行。三个 schema 分别约束计划、归一化事件和交付包；适配器 `scripts/adapter_qiling.py` 只做计划与离线解析，容器内 runner `scripts/qiling_runner.py` 只由 `scripts/sandbox_run.py` 启动。**计划 ready 只表示参数齐全，不代表能跑，更不代表漏洞成立。**

### 19.1 QilingPlan（`qiling-plan/1.0`）

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` / `tool` / `version` | string | ✅ | `qiling-plan/1.0` 与生成器版本 |
| `plan_id` | string | ✅ | `QPL-` 加 12 位十六进制；由计划内容（去掉 `plan_id`）派生 |
| `status` | enum | ✅ | `ready` / `blocked`；`ready` 不得带 blockers，`blocked` 必须 blockers 非空 |
| `run_id` / `intent_id` / `firmware_sha256` | string | ready 必需 | 绑定审计运行与 Intent；固件哈希必须 64 位十六进制 |
| `firmware_root` | string | ✅ | 容器内固件挂载根；目标与 rootfs 必须在其中 |
| `target` | object | ✅ | `{host_path, container_path, sha256, size, arch, bits, endian, elf_type, interpreter, needed, inside_rootfs}`；`interpreter` 可为 null |
| `rootfs` | object | ✅ | `{host_path, container_path, file_count}` |
| `runtime` | object | ✅ | `{backend: qiling, image, network: none, mode: sandbox, python}` |
| `execution` | object | ✅ | `{argv, guest_argv0, target, rootfs, env, stdin, stdin_host}`；`argv` 使用容器内路径 |
| `hooks` | array | ✅ | 每项 `{mechanism: syscall / api / libc / address, name, phase: enter / exit, args, signature}`；`args[]` 为 `{name, kind: string / string_array / int / hex / pointer}`；同一 mechanism+name+phase 不得重复 |
| `filters` | object | ✅ | `{version, trigger_markers, sink_hooks, max_events, max_string}`；ready 计划必须至少各有一个 trigger marker 与 sink hook |
| `budget` | object | ✅ | `{timeout_s}`；必须给出正整数 |
| `blockers` / `limitations` | array | ✅ / — | blocker 为 `{code, message, next_action}`，不能只写「失败」；`limitations` 可选 |

**blocker 码**：`FIRMWARE_ROOT_MISSING`、`TARGET_MISSING`、`ROOTFS_MISSING`、`TARGET_OUTSIDE_FIRMWARE`、`ROOTFS_OUTSIDE_FIRMWARE`、`TARGET_OUTSIDE_ROOTFS`、`ARCH_UNSUPPORTED`、`INTERPRETER_MISSING`、`LIBRARY_MISSING`、`TARGET_HASH_MISMATCH`、`RUN_ID_MISSING`、`INTENT_ID_MISSING`、`FIRMWARE_SHA_MISSING`、`BAD_ENV`、`STDIN_MISSING`、`TRIGGER_MARKERS_MISSING`、`SINK_HOOKS_MISSING`。没有触发标记或 sink Hook 时计划必须阻断，否则事件永远无法区分「普通运行」与「触发」。

### 19.2 QilingEvent（`qiling-event/1.0`）

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` / `event_id` / `seq` | string / string / int | ✅ | `qiling-event/1.0`；`event_id=QE-` 加 12 位十六进制；`seq` 从 1 起 |
| `run_id` / `firmware_sha256` | string | ✅ | 必须与导入包、黑板一致 |
| `mechanism` | enum | ✅ | `syscall` / `api` / `libc` / `other`；`system()` 是 API Hook，`execve` 是 syscall Hook，不得混写 |
| `hook` / `phase` | string / enum | ✅ | Hook 名；`enter` / `exit` |
| `classified_as` | enum | ✅ | `sink-hit` / `observed` / `failure` |
| `trigger` | bool | ✅ | `sink-hit` 必须为 true；`observed` / `failure` 不得为 true |
| `args` | object | ✅ | 归一化后的 Hook 参数；长字符串按 `max_string` 截断 |
| `source` | object | ✅ | `{path, line}`，指向原始事件日志，便于追溯 |
| `filter` | object | ✅ | `{version, rule_id, reason}`；`sink-hit` 的 `rule_id` 必须是 `trigger-marker` |
| `context` | object | — | PC、架构、位宽、线程等上下文 |

**判定权在适配器**：适配器重算 trigger（参数中任一字符串包含 trigger marker），并且只有 Hook 属于 `sink_hooks` 且命中标记才归为 `sink-hit`。runner 自报 `sink-hit` 但未命中时降级为 `observed` 并写 warning；普通 `connect()`、`open()` 等运行事件只能是 `observed`。

### 19.3 QilingImport（`qiling-import/1.0`）

| 字段 | 说明 |
|---|---|
| `schema` / `adapter{name,version}` | 导入包版本与适配器信息 |
| `run_id` / `intent_id` / `firmware_sha256` | 全包绑定；result、events、evidence、facts 任一不一致即拒绝 |
| `status` | `parsed` / `partial` / `failed`；`parsed` 时 `errors` 必须为空，不完整不得伪装完整 |
| `plan_id` / `backend{name,version,image}` | 计划 ID 与 Qiling 后端版本、镜像 |
| `execution` | `{mode: sandbox / offline, host_fallback: false, sandbox}`；`host_fallback` 不是 false 即 `POLICY` 失败 |
| `result` | EmulationResult；FAILED/BLOCKED/TIMED_OUT → 导入 `failed`，PARTIAL → `partial`，SUCCESS 不得标 `failed` |
| `events` / `evidence` / `facts` | 逐项按各自 schema 校验并查重；fact 的 `evidence_refs` 与 result 的 `evidence_refs` 不得悬空 |
| `errors` / `limitations` / `filters` | 解析错误、已知限制、生效过滤规则 |
| `counts` | `events` / `sink_hits` / `observed` / `failure_events` / `parse_errors` / `evidence` / `facts` 及 `by_mechanism` / `by_classification`；必须与实际数组交叉一致 |

### 19.4 执行与证据边界

- **唯一执行入口**：`adapter_qiling.py run` 只调用 `sandbox_run.py`；容器参数、资源策略、槽位与预算都由沙箱决定，适配器不能放宽。计划被阻断时直接写 BLOCKED，不启动沙箱。
- **状态不混淆**：沙箱报告 `mode` 不是 `sandbox`（例如 host）或 `host_fallback=true` → `BLOCKED` 且 `failure.category=policy-blocked`；计划自身阻断 → `BLOCKED` 且 `plan-blocked`；沙箱不可用或准入拒绝 → `BLOCKED` 且 `sandbox-unavailable`；超时 → `TIMED_OUT`；runner 崩溃或退出非 0 → `FAILED`。这些状态不能互相顶替。
- **证据只来自命中**：目标文件生成 static 证据，运行本身生成 emulation 证据，只有 `sink-hit` 事件生成漏洞证据；`observed` 事件不生成证据，不产生 finding。`SUCCESS` 只表示 runner 正常结束，不等于漏洞成立，也不能让候选直接进入 `validated` / `confirmed`。
- **原始日志可追溯**：`events[].source.path` 指向 runner 的原始 JSONL；`filter.version/rule_id` 固定过滤规则版本。事件被截断时导入状态必须是 `partial`。
- **退出码**：`0` 正常、`1` 解析失败/FAILED、`2` 用法、`3` 计划阻断或 BLOCKED、`4` 策略拒绝、`5` 资源准入拒绝、`124` 超时。


**当前验证边界（不得省略）**：2026-11-02 / 2026-11-03 已在 Ubuntu 24.04.5 + Docker 29.9.2 上真实执行 `qiling_runner.py`。Qiling 1.4.6 的静态 MIPS 受控目标 `qltest-static` 产出 1 条 sink-hit、`SUCCESS` 结果、3 条 evidence / 3 条 fact，并导入黑板（evidence 4 / facts 4 / intents 1 / emulation_results 1，`verify` 通过），记录见 `assets/qiling/real-run-static/README.md`。Qiling 1.4.11 的固件动态 MIPS/musl `busybox cat /etc/QLTEST` 成功，guest 退出码 0，4 条事件中 `open("/etc/QLTEST")` 命中 sink，产出 1 条 sink-hit、`SUCCESS`、3 条 evidence / 3 条 fact，黑板计数相同，记录见 `assets/qiling/real-run-busybox-sink/README.md`；`qiling_runner.py` 已兼容 1.4.11 把 `INTEGER` 改名为 `INT`。Qiling 1.4.6 对动态 musl `busybox` 的 `FAILED / memory-error / UC_ERR_WRITE_UNMAPPED` 只能说明该版本/该镜像的加载问题，不能概括为 Qiling 不支持 musl；旧动态失败产物已删除。动态记录只覆盖 `cat /etc/QLTEST` 一个 applet，不覆盖网络、服务、多 applet 或厂商内核，`SUCCESS` / `sink-hit` 都不是漏洞结论。对应自检仍使用合成 MIPS ELF 与假 sandbox，只证明计划、过滤、归一化、状态分类、Hook 安装边界与黑板导入，不替代真实执行。另有一个已知边界：blocked 计划若缺 `firmware_sha256`，`qiling-import` 仍要求 64 位哈希，会把该计划判为契约失败。

## 20. SchedulerRules / SchedulerResult（`scheduler-rules/1.0` / `scheduler-result/1.0`）

调度层只做确定性编排：规则把已存在的 Fact 映射成 Intent，`claim` 做统一资源准入，`complete` 把执行结果写回黑板。规则不执行命令，不调用 Qiling/QEMU，也不产生漏洞结论；真正的执行仍由 `sandbox_run.py` 与适配器完成，且必须再次经过资源准入。

### 20.1 SchedulerRules

```json
{
  "schema": "scheduler-rules/1.0",
  "version": "2026-11-05",
  "rules": [
    {
      "id": "R-SERVICE-DYNAMIC",
      "version": "1",
      "when": {
        "fact_type": "service",
        "value_present": ["port"],
        "value_truthy": ["open"]
      },
      "intent": {
        "type": "dynamic-validation",
        "description": "验证 {value.name} 的端口 {value.port}",
        "target": "{target}",
        "priority": 60,
        "params": {"port": "{value.port}"},
        "timeout_seconds": 120,
        "max_retries": 1,
        "stop_conditions": ["目标端口无响应"],
        "expected_outputs": ["evidence", "fact"]
      }
    }
  ]
}
```

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `scheduler-rules/1.0` |
| `version` | string | — | 规则集版本，写入 Intent 的 provenance |
| `rules` | array | ✅ | 非空；每条规则一个对象 |
| `rules[].id` | string | ✅ | `^R-[A-Za-z0-9][A-Za-z0-9._-]*$`；文件内唯一 |
| `rules[].version` | string | ✅ | 规则版本；与 `id` 一起进入去重键 |
| `rules[].enabled` | bool | — | 省略视为启用；为 false 时 `plan` 跳过 |
| `rules[].when` | object | ✅ | 匹配条件，见下 |
| `rules[].intent` | object | ✅ | Intent 模板；`type` / `description` / `target` 必填 |
| `rules[].depends_on` | array | — | 依赖的规则 ID；必须指向同一文件，不允许自依赖 |

`when` 只接受四个键，未知键报 `UNKNOWN_FIELD`（拼错的谓词不会被静默忽略）：

| 键 | 语义 |
|---|---|
| `fact_type` | Fact 类型字符串或非空数组；必须是已知 `FACT_TYPES` |
| `value_present` | 字符串数组；`fact.value` 中这些键必须存在 |
| `value_truthy` | 字符串数组；这些键的值必须为真（非空、非 0、非 false） |
| `value_equals` | 非空标量对象；逐键严格相等 |

模板占位符写作 `{value.path}`、`{target}`、`{fact_id}`，只支持点路径，不支持嵌套花括号或表达式。渲染采用 Fact 的字段；`target` 依次取 `value.target` / `value.path` / `value.binary` / `value.service` / `value.name` / `value.port`，都没有时回落到 `fact_id`。

规则模板的 `priority` 必须在 0..100；`timeout_seconds` ≥1；`max_retries` 0..10；`params` 必须是对象；`stop_conditions` / `expected_outputs` 必须是字符串数组。规则 ID 重复报 `DUPLICATE_ID`，依赖不存在报 `DEPENDENCY_MISSING`，依赖成环报 `DEPENDENCY_CYCLE`。

### 20.2 从规则到 Intent

- 每个命中的 Fact 生成一条 `intent/1.1`：`from=[fact_id]`、`creator=rule:<id>@<version>`、`provenance={rule_id, rule_version, fact_ids, hint_boost, hints}`。Fact 与规则的对应关系必须能反查，不能只留下「系统自动生成」。
- `dedupe_key = "sched:" + sha256(canonical_json({rule, version, type, target, params}))`。同一规则对同一目标只建一次；重复 `plan` 返回 `deduped`，不追加事件、不增长 `revision`。
- `intent_id = "I-" + sha256(dedupe_key)[:12]`；同一输入稳定复现，不依赖当前时间或随机数。
- 优先级取模板 `priority`，Hint 命中时每条 +5、封顶 +15。Hint 只影响排序，不能把 Intent 变成 `claimed`，也不能绕过 Gate。
- `depends_on` 在规则层声明；`readiness` 返回 `READY` / `WAITING` / `BLOCKED`。依赖 Intent 失败、取消或缺失时分别报 `DEPENDENCY_FAILED` / `DEPENDENCY_CANCELLED` / `DEPENDENCY_MISSING`，不得让任务永久停在 `WAITING`。

### 20.3 SchedulerResult

```json
{
  "schema": "scheduler-result/1.0",
  "intent_id": "I-7f2416177e61",
  "run_id": "RUN-2026-11-05",
  "firmware_sha256": "aaaaaaaa...",
  "status": "SUCCESS",
  "worker": "agent-1",
  "attempt": 1,
  "started_at": "2026-11-05T10:44:46Z",
  "finished_at": "2026-11-05T10:45:12Z",
  "summary": "端口可达并复现 execve",
  "evidence": [{"schema": "evidence/1.1", "evidence_id": "E-RES", "run_id": "RUN-2026-11-05", "firmware_sha256": "aaaaaaaa...", "type": "dynamic", "observed_at": "2026-11-05T10:45:00Z", "status": "parsed", "source": {"type": "dynamic", "tool": "sandbox"}, "event": {"type": "execve", "trigger": true}}],
  "facts": [{"schema": "fact/1.0", "fact_id": "F-RES", "run_id": "RUN-2026-11-05", "firmware_sha256": "aaaaaaaa...", "type": "syscall", "value": {"name": "execve"}, "evidence_refs": ["E-RES"], "source": {"type": "dynamic", "tool": "sandbox"}, "observed_at": "2026-11-05T10:45:00Z"}]
}
```

| 字段 | 类型 | 必需 | 说明 |
|---|---|---|---|
| `schema` | string | ✅ | `scheduler-result/1.0` |
| `intent_id` / `run_id` / `firmware_sha256` | string | ✅ | 必须与目标 Intent 及黑板绑定一致 |
| `status` | enum | ✅ | `SUCCESS` / `PARTIAL` / `FAILED` / `BLOCKED` / `NOT_APPLICABLE` / `TIMED_OUT` |
| `worker` / `attempt` | string / int | — | 与 `claim` 时一致；`attempt` ≥1 |
| `started_at` / `finished_at` | string | 条件 | `finished_at` 必填；ISO 8601 带时区 |
| `summary` | string | — | 人类可读摘要，不替代结构化证据 |
| `evidence` | array | 条件 | 每条完整 `evidence/1.1`；必须自带 `run_id` 与 `firmware_sha256` |
| `facts` | array | 条件 | 每条完整 `fact/1.0`；必须自带 `run_id` 与 `firmware_sha256` |
| `failure` | object | 条件 | `FAILED` / `BLOCKED` / `TIMED_OUT` 必填 `{code,message,category,retryable}` |
| `limitations` | array | 条件 | `PARTIAL` 必须非空；说明没覆盖什么 |
| `artifacts` / `resource_usage` | array / object | — | 原始产物与资源用量；产物逐项校验 `path`+`sha256` |

约束：

- `evidence` / `facts` 的 `run_id` 与 `firmware_sha256` 是**必填**字段。校验器只做交叉校验，不会替你补字段；缺字段就是契约失败。
- 同一结果内 `evidence_id` / `fact_id` 不得重复（`DUPLICATE_ID`）；`fact.evidence_refs` 只能引用本结果里的证据，悬挂报 `DANGLING_EVIDENCE`。
- `SUCCESS` / `PARTIAL` 必须至少产生一条 Evidence 或 Fact，否则 `RESULT_NO_OUTPUT`。执行「成功」但什么都没留下，不是成功，只是没有输出。
- 失败状态必须说明可重试性：`retryable=true` 才允许回到 `open`；`false` 直接 `failed`。`TIMED_OUT` / `BLOCKED` 不得折叠成「没有发现」。

### 20.4 调度语义与审计

| 动作 | 行为 | 失败码 |
|---|---|---|
| `plan` | 按规则拓扑顺序评估 Fact；只对 `--write` 落盘；重复评估由 `dedupe_key` 去重 | `DEPENDENCY_MISSING` / `DEPENDENCY_CYCLE` / `RULE_INVALID` |
| `next` | 只列 `READY` 的 Intent，按 `-priority`、`created_at`、`intent_id` 排序 | — |
| `claim` | 校验 READY、`open`、`worker`；用 `check_request` 对拍策略，拒绝时 exit 5 且 Intent 保持 `open`；同时按 `--lease-seconds` 写租约（默认 900，范围 1..86400） | `RESOURCE_DENIED` / `INTENT_NOT_READY` / `INTENT_NOT_OPEN` / `LEASE_INVALID` |
| `heartbeat` | 仅当前持有者可续租；要求 `claimed` 且 `worker` 一致，重算 `expires_at` 并写 `INTENT_LEASE_RENEWED` | `INTENT_NOT_CLAIMED` / `WORKER_MISMATCH` / `LEASE_INVALID` |
| `reclaim` | 把租约过期的 `claimed` 转回 `open`，`reason=lease_expired`，保留 `attempts` 与结果引用；`--dry-run` 只报告 | `STATE_MISMATCH` / `ILLEGAL_TRANSITION` |
| `complete` | 校验 result 与 Intent/worker/attempt 及租约；先写 Evidence/Fact，再改 Intent 状态；租约过期拒绝回写 | `RESULT_INVALID` / `INTENT_NOT_CLAIMED` / `WORKER_MISMATCH` / `ATTEMPT_MISMATCH` / `LEASE_EXPIRED` |
| `backtrack` | 从当前阶段显式回退，证据必须存在 | `PHASE_MISMATCH` / `NOT_A_BACKTRACK` / `REASON_REQUIRED` |

`claim` 只做准入检查，不长期占用并发槽位；真正的槽位、预算与超时由 `sandbox_run.py` 在启动时获取。这样不会出现「调度器领了任务但不执行，槽位被空占」的情况。`complete` 先写结果再改状态，保证不会出现 Intent 已 `done` 却查不到对应证据的窗口；状态事件失败时证据仍在，可按 `result_refs` 审计并人工修复。

`stop_conditions` 由规则写入 Intent，执行器在满足时必须返回 `NOT_APPLICABLE` 或 `FAILED` 并说明原因，不能继续重试。调度器负责重试上限（`attempts <= max_retries` 时才回 `open`），不负责解释业务停止条件。

阶段前进与回退都写入事件日志：`PHASE_ADVANCED` 只能逐阶段前进，`BACKTRACK` 只能从当前阶段回退；两者都必须带原因，`BACKTRACK` 还必须带触发证据。事件日志是唯一真相源，快照丢失可从日志重放。

**租约与回收**：`claim` 写入 `lease={worker, acquired_at, heartbeat_at, expires_at, ttl_seconds}`，默认 900 秒，最大 86400 秒；`--lease-seconds` 越界或不是整数报 `LEASE_INVALID`，退出 **2**。`heartbeat` 只有持有者可调用，续租时重新计算 `expires_at` 与 `heartbeat_at`；即使租约已过期，只要 Intent 仍是 `claimed` 且 `worker` 一致，仍可续租恢复。

`reclaim` 只处理租约已过期的 `claimed`：没有 `lease` 的旧式 `claimed` 视为未过期，不回收；`lease` 不是对象也不回收；`expires_at` 缺失或非法则按过期处理。回收把状态改回 `open`、`reason=lease_expired`，保留 `attempts` 与既有 `result_refs`，不删除任何 Evidence / Fact；下一次 `claim` 令 `attempts+1`，新租约从新的领取时刻重新计算。`--dry-run` 只列出将要回收的 Intent，不写事件。

`complete` 在 Intent 为 `claimed` 且租约过期时报 `LEASE_EXPIRED` 并拒绝回写，Intent 保持 `claimed`；此时应先 `heartbeat` 续租，或 `reclaim` 后重新领取。资源准入仍只在 `claim` 执行：拒绝时退出 **5** 且 Intent 保持 `open`；`heartbeat` / `reclaim` / `complete` 不重做准入，也不改变退出码 5 的含义。

命令行示例：

```bash
python scripts/board_scheduler.py plan --workspace runs/audit --rules scheduler-rules.json --write
python scripts/board_scheduler.py next --workspace runs/audit --limit 10
python scripts/board_scheduler.py claim --workspace runs/audit --intent I-7f2416177e61 --worker agent-1 --policy sandbox-policy.json --lease-seconds 900
python scripts/board_scheduler.py heartbeat --workspace runs/audit --intent I-7f2416177e61 --worker agent-1 --lease-seconds 900
python scripts/board_scheduler.py reclaim --workspace runs/audit --dry-run
python scripts/board_scheduler.py complete --workspace runs/audit --intent I-7f2416177e61 --result result.json
python scripts/board_store.py advance --workspace runs/audit --to-phase P2 --reason "进入动态验证" --evidence E-SVC
python scripts/board_scheduler.py backtrack --workspace runs/audit --from-phase P2 --to-phase P1 --reason "端口证据不足" --evidence E-SVC
```

退出码：`0` 正常；`1` 契约/状态失败；`2` 用法错误；`5` 资源准入拒绝。

## 21. ToolIndex（tool-index/1.0）

Phase 0 之前由 `scripts/tool_index.py` 生成，记录本次审计实际能用的工具、版本与能力覆盖。它不是漏洞证据，也不替代 Phase 1 的格式侦察：索引只回答「这台机器上有什么、缺什么、缺了走哪条替代路径」，不回答「固件里有什么」。产物固定写入 `00-tool-index.json`，随审计交付物保存。

工具与能力清单不在 Python 里，而在 `assets/tool-registry.json`（`tool-registry/1.0`，当前 41 个 tools / 54 个 capabilities）。新增或调整工具只改该 JSON；`tool_index.py` 只负责加载、校验、探测与渲染。注册表缺失、JSON 损坏、未知字段、重复 ID、悬空的能力/工具引用都会以退出 2 fail-closed，不会带着半份清单继续探测。`--registry <file>` 可以切换到另一份注册表，索引会把实际来源与 sha256 写进 `registry` 字段，便于复算。

```bash
python scripts/tool_index.py --profile all --out fw-audit/<target>/00-tool-index.json
python scripts/tool_index.py --registry assets/tool-registry.json --only qiling --json
python scripts/tool_index.py --require moria --require ast-grep
python scripts/tool_index.py --install binwalk --yes
```

### 21.1 顶层字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `schema` | string | 固定 `tool-index/1.0` |
| `tool_version` | string | 生成器版本，当前 `1.0` |
| `generated_at` | string | UTC ISO 8601，探测完成时间 |
| `host` | object | `os` / `release` / `machine` / `python` / `is_windows`；用于解释平台相关缺口 |
| `registry` | object | `schema`（`tool-registry/1.0`）、`version`（注册表日期）、`tools`（注册表总数，当前 41）、`source`（`assets/tool-registry.json` 或 `--registry` 指定的路径）、`sha256`（注册表原始字节的哈希） |
| `profile` | string | 请求的 `all` / `phase0` / `extract` / `static` / `dynamic` |
| `summary` | object | 本次**实际探测**的工具计数：`total` / `available` / `degraded` / `missing`，四者满足 `total = available + degraded + missing` |
| `tools` | array | 探测结果，按注册表顺序；`--only` 时只含所选工具 |
| `capabilities` | array | `atomic-capabilities.md` 的 54 项能力映射；`--profile` / `--only` 时只保留相关项 |
| `phases` | array | 阶段就绪度；`all` 时为 P0/P1/P3/P4，按 profile 时只含对应阶段 |
| `notes` | string | 固定说明：只做版本探测、不读固件、安装必须显式确认 |

`summary.total` 是本次选中的工具数，不是 `registry.tools`。用 `--only moria` 时 `total` 为 1，不能拿它推断环境里只有 1 个工具。

### 21.2 tools[]

| 字段 | 说明 |
|---|---|
| `id` | 稳定工具 ID，与 CLI `--only` / `--require` / `--install` 使用同一套名字 |
| `kind` | `cli` / `family` / `python-module` / `python-runtime` / `container-image` |
| `capabilities` | 该工具能支撑的能力编号，如 `E2`、`D5` |
| `argv` / `alternates` | 版本探测命令候选；`alternates` 用于 `sg` 之类命名冲突时的退路 |
| `module` | `python-module` 的导入名 |
| `images` | `container-image` 的候选镜像（如 `iot-fw/qiling:1.4.11`、`:latest`） |
| `prefix` / `prefixes` / `extra_paths` | 非 PATH 安装位置的补充搜索路径 |
| `required` / `recommended` | 是否为硬依赖 / 推荐工具；只影响摘要语气，不改变退出码 |
| `docs` | 官方文档或仓库 URL |
| `install` | `kind`（`uv` / `cargo` / `pip` / `docker-build` / `system` / `build-from-source` / `manual`）、`auto`（能否自动执行固定配方）、`argv`、`requires`（前置命令）、`shell`（人工安装命令）、`docs`、`notes` |
| `fallback` | `tools`（可替代实现）与 `impact`（降级对结论的影响） |
| `notes` | 选型说明 |
| `version_must_contain` | 版本字符串必须包含的标记；为空表示不限制 |
| `found` | PATH / 模块 / 镜像是否找到；与 `status` 分开，避免把「找到但版本命令失败」误报为 missing |
| `status` | `available`（找到且探测成功）/ `degraded`（找到但版本未知或探测失败）/ `missing`（未找到） |
| `version` / `path` | 探测到的版本与可执行文件路径；缺失时为 `null` |
| `probe` | `argv`（实际执行）、`returncode`、`ok`、`duration_ms`、`error`（`not-found` / `timeout` / 启动错误等） |
| `phases` | 该工具参与的阶段，如 `["P1"]`；P0 只对 python/file/uv 额外标注 |

探测只执行版本命令或镜像 inspect，不接收固件路径，不执行固件。除 `PATH` 外还检查 `~/.local/bin`、`~/bin`、`~/.cargo/bin`、`/usr/local/bin`、`/opt/homebrew/bin`、`/snap/bin`（只用于查找，不改变进程 `PATH`）。Windows 上的 `.cmd` / `.bat` 经 `COMSPEC /d /s /c` 包装，单次超时默认 5 秒（`--timeout` 可调，限制在 0.5–30 秒）；`unsquashfs` / `afl-fuzz` 的版本命令固定返回 1，只要输出可解析出版本仍记为 `available`。

### 21.3 capabilities[]

| 字段 | 说明 |
|---|---|
| `id` / `name` | 能力编号与名称，编号与 `references/atomic-capabilities.md` 一致 |
| `phases` | 能力所属阶段 |
| `status` | 见下 |
| `primary` | 首选实现；为空表示没有单一首选 |
| `available_tools` | 本次选中且 `found=true` 的实现 |
| `missing_tools` | 本次选中但未找到的实现；未选中的工具不会出现在这里 |
| `manual` | 无工具能力的人工路径（如物理故障注入），仅 `manual` 状态使用 |
| `fallback` | 降级路径说明 |

能力状态判定：

| 状态 | 条件 |
|---|---|
| `available` | `primary` 已找到；没有 primary 时至少一个实现找到 |
| `degraded` | primary 缺失，但还有其它实现可用 |
| `missing` | 该能力登记的实现全部缺失；`--only` / `--profile` 局部索引下只指本次选中的实现，不代表全局缺失 |
| `manual` | 能力本身没有工具实现，只能人工完成（E9、F3、B5–B8、D2/D3、N2–N4、H1–H4 等） |

`manual` 不是缺失，不能因为出现 manual 就判定审计不可做；但必须在报告里写明该能力未自动化、结论强度受限。

### 21.4 phases[]

| 字段 | 说明 |
|---|---|
| `id` / `name` | `P0` 度量、`P1` 提取、`P3` 审计、`P4` 动态验证 |
| `status` | `ready` / `partial` / `blocked` / `n/a` |
| `available_tools` / `missing_tools` | 参与该阶段的能力所对应的实现，去重排序 |

- `P0` 特殊处理：`python` 缺失为 `blocked`；`python` + `file` 都在为 `ready`；只有 `python` 为 `partial`；本次未选 `python` 为 `n/a`。`uv` 参与 P0 工具列表，但不单独决定 P0 状态。
- `P1` / `P3` / `P4`：该阶段相关能力全部 `available` 为 `ready`；至少有一个 `available` 或 `degraded` 为 `partial`；全部 `missing` 为 `blocked`；该阶段没有相关能力为 `n/a`。`partial` 表示「能开工但有缺口」，不是硬阻断；缺口必须按 `fallback` 降级并记录。
- `--only` 会缩小参与统计的工具集合，阶段状态随之变化。做全量审计决策时不要用 `--only` 的局部结果代替全量索引。

### 21.5 命令行与退出码

| 参数 | 行为 |
|---|---|
| `--out PATH` | 写 `tool-index/1.0`；目录不存在时创建 |
| `--json` | 把同一份 JSON 打到 stdout；与文本摘要互斥 |
| `--only a,b` | 只探测指定工具；未知 ID 退出 2 |
| `--profile NAME` | `all` / `phase0` / `extract` / `static` / `dynamic`，按阶段筛选工具与能力 |
| `--require ID` | 可重复；索引生成后检查，必需工具不满足退出 3 并点名 |
| `--strict` | 与 `--require` 连用：工具必须版本已知，`degraded` 也算不满足 |
| `--docs` | 只打印工具与官方文档 URL，不探测 |
| `--install ID` | 可重复；显式请求安装。无 `--yes` 时只打印计划 |
| `--yes` | 确认执行脚本内置的固定安装配方；没有它绝不执行 |
| `--quiet` | 不打印文本摘要；`--out` 仍写文件 |

退出码：`0` 索引正常；`1` 安装失败或有工具只能人工安装；`2` 用法错误、未知 ID，或 `--install` 未加 `--yes` 且存在可执行计划；`3` `--require` 的工具缺失（`--strict` 下版本未知也算）。

安装策略是「固定配方 + 显式确认」，不是「运行时抓网页自动装」：脚本内置可审计的 `uv` / `cargo` / `pip` / `docker build` 命令，先检查 `uv`、`docker`、`git`、`cmake`、`c++` 等前置；moria、Ghidra、radare2 等没有稳定自动配方的工具只打印官方文档和人工命令，返回 1。这样避免把远端页面内容当成指令执行，也避免未经批准改动宿主机。

### 21.6 与 Phase 0 的边界

- 索引在 `fw_triage.py` 之前跑；`00-tool-index.json` 与 `00-metrics.json`、`00-scope.md` 一起保存。
- `summary.missing` 或 `phases[].status=blocked` 不自动终止审计：先看 `fallback`，能降级就降级并记录；确实没有替代路径时再向用户说明需要安装什么、为什么。
- `--require` 是给「已确定打法」的硬门槛用的，例如已决定用 moria 做多压缩后端解包；不要在还没侦察前就把所有推荐工具都设成 required。
- 当前 `coverage_gate.py` 不消费 `tool-index`；它不能作为门禁通过或漏洞存在的证据。若后续接入门禁，应作为「覆盖说明」输入，而不是 PASS 条件。
