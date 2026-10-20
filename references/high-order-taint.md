# 高阶污点漏洞：方法与可执行判据

> 本文只讲一件事：**「请求 1 写、请求 2 读」这类漏洞怎么证明成立**，以及怎么把结论做成可以被门禁否决的形状。
>
> 方法来源：Bridge — *High-Order Taint Vulnerabilities Detection in Linux-based IoT Firmware*，IEEE S&P 2026, pp. 3320–3339（中科院信工所 / 蚂蚁 / 清华）。本文的算法细节与阈值**逐条对照其开源 artifact**（`pjqwudi123/bridge:1.0`）的实际代码复算，不采信二手转述；凡属本文作者归纳而非代码中直接可见的，都标了「推论」。

## 0. 判据先行：什么才算「高阶」

普通（一阶）漏洞的链在**一个请求内**闭合：

```
请求 → handler → 解析参数 → … → sink
```

高阶漏洞的链被**持久化存储**切成两半：

```
请求 1（action A）：用户输入 → nvram_safe_set("k", v)      ← 写面
请求 2（action B）：nvram_safe_get("k") → … → system(buf)  ← 读面 + sink
```

由此得到**唯一可机械判定的定义**（Bridge 的输出也是这么组织的）：

| 判据 | 含义 | 不满足的后果 |
|---|---|---|
| **C1 写面与读面分属不同 action** | 同一 action 内读写同一键 = 一阶，不是高阶 | 不得计入高阶；报成高阶即虚增 |
| **C2 键在两端字面一致** | 拼出来的键必须先恢复成常量子串 | 配不上对，链根本不存在 |
| **C3 读面到 sink 真实可达** | 值被送进 `system` / 定长拷贝等 | 只是「读了」，不是漏洞 |
| **C4 每一端有地址 + 证据** | 写点地址、读点地址、sink 地址 | 无法复核 = 无法证伪 |

⚠️ **C1 是最容易被糊弄的一条。** 报告里写「Source: nvram `wan_ifname`（写入面为恢复配置导入）」看上去闭合了，但如果没有指明**写它的 action** 和**读它的 action 是哪一个**，就无法排除「其实是同一个 handler 里读自己刚写的值」——那种情况只是一阶，甚至可能是误报。

## 1. 三阶段流水线与本 skill 的对应物

| 阶段 | Bridge 做什么 | 产物 | 本 skill 对应 |
|---|---|---|---|
| **① 入口点** | 识别 AEH（动作入口处理器）+ IPF（用户可控输入的解析函数） | `pre.txt`（边界二进制 / AEH / IPF） | Phase 2 动作关键字枚举 + Phase 3 Track A 的 source 识别；词表见 `assets/ipc-functions.json` |
| **② BDG** | 以 IPF 为源、IPC 写为汇（第一段）；以 IPC 读为源、危险函数为汇（第二段）；按存储键 join | `BDG.txt` | `scripts/taint_graph.py` 的 `keys/chains` |
| **③ ADG** | 跨二进制、跨库追踪 action handler 之间的**控制流**转移 | `action_result_maps.txt` | `taint_graph.py` 的 `adg` |
| **结论** | BDG × ADG ⇒ 高阶候选 | `vuln_result.txt` | `taint-graph.json` + 门禁 G7 |

三者关系是**串行依赖**，不能跳：没有 AEH 就不知道「action A/B」是什么；没有 ADG 就不知道请求 2 是怎么被触发的（可能根本没有外部入口）。

## 2. 阶段一：动作入口（AEH）

**AEH = 处理某个动作关键字（`SetVLAN`、`GetWanSettings`…）的函数或基本块集合。** 落地有三种形态，识别优先级 `callback_key > func_table > strcmp_like`：

### 2.1 三种形态与阈值

| 形态 | 特征 | 阈值（artifact 实测） | 常见误报源 |
|---|---|---|---|
| **注册回调** | 同一次调用里同时传入**常量字符串**和**函数指针**：`websFormDefine("SetWanSettings", sub_465E68)` | 与前端动作名匹配数 **≥ 10** | `qsort`/`signal`/`scandir` 也传函数指针 → 必须要求「常量串 + 函数指针」同调 |
| **函数指针表** | `.data` 段成对的 `(字符串指针, 函数指针)`：`DCD aUpgradeCgi / DCD sub_304C8` | 与前端动作名匹配数 **≥ 20** | 表里混着 `upgrade.cgi`、`*.js` 等文件名 → 按后缀过滤 |
| **嵌套比较链** | 多层 `if-else` + `strcmp`/`strncmp`/`strcasecmp`/`memcmp`/`strstr` | 见下 | 普通业务逻辑里的大量 strcmp |

### 2.2 嵌套比较链的识别与「handler 边界」算法

这是最麻烦的一种，因为一个函数里几十个 `strcmp` 连成链，**没有显式的函数边界**。Bridge 的做法（`action_handler_infer.py: infer_nested_comparison_keys_in_text`）：

1. **找汇聚点（nested sink）**：函数内某基本块**入度 ≥ 10** —— 这是所有 `else` 分支最终汇合的位置。
2. **找比较函数**：同一函数内某个 strcmp 类函数**被调用 ≥ 10 次**。
3. **筛比较块**：块内**只有 1 个调用点**且该调用是 strcmp 类。
4. **定链形**：头节点允许多入度；中间节点 **1 入 2 出**；尾节点指向汇聚点。
5. **定 handler 边界**（`_get_action_entry_v1`，action_type=`blocks`）：
   - 每个 key 取比较块的后继中**能到达汇聚点**的那一支作起点 `N`；
   - `handler = descendants(N) ∩ descendants(reverse(sink))`（用可达性交集，不用 `all_simple_paths`——路径爆炸）；
   - 两支都不可达汇聚点时，回落到**函数 exit_block** 的可达交集；
   - 汇聚点的选择用 `min |in_degree - 链长|` 校准。

> **推论（实践要点）**：这意味着「一个 action 的 handler」在二进制里**不是一段连续地址**，而是一个**基本块集合**。所以证据里必须写清 `(function_addr, [block_addrs])`，而不是只写一个函数名——否则复核时无法判断你圈的范围对不对。

### 2.3 污点源（IPF）识别

IPF = 把用户可控数据解析出来的函数。两类：

**库里现成的**（直接用符号，`ipc-functions.json → ipf_libc_sources`）：`websGetVar`、`cgiFormString`、`mxmlFindElement`、`json_object_get_string`、`recv/recvfrom/read/fgets`、`getenv`…

**固件自造的**（`TaintSourceInfer._analyze`），三个模型 + 三道闸：

| 闸门 | 值 | 作用 |
|---|---|---|
| 调用次数 | **≥ 100**（ASUS 特例 ≥ 30） | 键值函数必然被到处调用；冷门函数不可能是 |
| 常量实参占比 | `len(con_strs) ≥ num * 2/3` | 同一个函数在 2/3 以上调用点都收到常量字符串 → 它在按 key 查表 |
| 数据流规模 | 返回值的反向 DDG **≤ 100 节点** | 超过就不是简单的「查表返回」，避免把大函数误判成 IPF |

模型：

1. **返回值型**：函数里**有循环**且循环内**有 strcmp**，返回值是循环变量的回填（`identify_key_value_one`）。
2. **出参型**：循环 + strcmp + **指针参数在循环里递增**（`identify_key_value_two`）。
3. **包装型**：自身没有特征，但调用了上面两类（`identify_key_value_three`），逐层向上确认。

ASUS 另有一条特例：调用链里出现 `hsearch_r`（hash 检索）即视为键值函数。

## 3. 阶段二：BDG（两阶段污点 + 按键 join）

**BDG 的节点是「存储键」，不是函数。** 构建分两段，两段**跑的是同一个污点引擎，只是 source/sink 配置相反**：

```
第一段（边界二进制，写侧）
  sources = IPF(该二进制的污点源)
  sinks   = IPC 写原语（nvram_safe_set / uci_set / sendto / fopen(w) / apmib_set…）
  产出    source_sink 映射 + 「sink 地址 → 存储键」字典（nvram_set_dict / apmib_set_dict）

第二段（其它二进制，读侧）
  sources = IPC 读原语（nvram_safe_get / uci_get / recvfrom / opendir…）
  sinks   = 危险函数（定长拷贝 + 命令执行）
  产出    「键 → 读到该键的函数 → 可达的 sink 地址」

join
  BDG[key] = {"set": {写它的二进制: {sink_addr: [sources]}},
              "get": {读它的二进制: {source_addr: {sink_kind: [sink_addrs]}}}}
```

关键点：

- **必须按 sink 地址反查存储键**。污点引擎只知道「这个 `nvram_safe_set` 调用点是汇」，键是**在调用点按参数位置取常量**得到的（见 §4）。取不到常量 → 这个 sink 进 `taint_storages_failed`，**不能默认它无害**。
- **只有「边界二进制写过的键」才值得追**（`if candidate_taint_storage_name in taint_storage`）。这是降噪的关键：镜像里几千个 nvram 键，绝大多数从来没人写。
- **sink 只分两类**（artifact `SecurityCheck.sinks`）：`weak_copy`（`strcpy/strncpy/memcpy/memmove/sprintf/snprintf/sscanf/strcat/strncat`，带栈偏移与长度约束分析）与 `command_exec`（`system/popen/exec*` 与厂商包装）。**把「读到了」当「有漏洞」是这类工作最常见的虚报来源。**

## 4. OD-ICP：键的常量恢复（决定 C2 成不成立）

动态拼出来的键是这套方法的**第一道坎**。真实固件里大量出现：

```c
sprintf(buf, "%s_management_link", prefix);   // → lan0_management_link
nvram_safe_set(buf, value);
```

Bridge 的解法是**按需过程间常量传播（OD-ICP）**，不是全局常量分析：

**过程内**：在 IPC 调用的那个基本块里往前找实参定义，按「来源类型」分四种情况（`arg_parse.py: get_constant_context_v1`）：

| 来源标记 | 含义 | 取值方式 |
|---|---|---|
| `G` | 全局/只读段地址 | 读该地址的字符串（上限 **256** 字节） |
| `S` | 栈槽地址 | 追到**写该栈槽的那条指令**（`T` 标记），取立即数 |
| `T` | 指令立即数 | 直接就是值 |
| `I` | 整数 | 直接就是值 |

取不到就 `None`——**不猜**。循环里若迭代次数已知则直接算，否则按初值做保守估计。

**过程间**：若过程内定不出值，则对**处理该变量的自定义函数**再做一次过程内分析，并把全局变量、栈指针、返回值的更新同步回原调用点。落到图上就是：

1. 以 IPC 原语为叶子建**子图**（`induced_subgraph(ancestors(leaf))`）；
2. 对子图做 **DFS 后序遍历**，把每个节点的上下文**从后继并到前驱**（`_update_ipc_subgraph_context`）——这样「根节点（= action handler）」自然继承它所有传递调用里出现过的 (键, 值)；
3. 根节点（`in_degree == 0`）的上下文并集 = 该 action 的 IPC 足迹。

`taint_graph.py recover` 实现了其中**三条确定能做**的规则，拼不出来就显式记 `unknown`：

| 规则 | 例子 | 标记 |
|---|---|---|
| 字面量 | `nvram_safe_set("lan0_management_link", v)` | `literal` |
| 局部常量 | `char *k = "wan_ifname"; nvram_safe_get(k);` | `local-const` |
| 缓冲区填充 | `snprintf(buf,64,"%s_%s","lan0","link"); nvram_safe_set(buf,v)`<br>`strcpy(buf,"a"); strcat(buf,"_b");` | `fill-composed` |
| 拼不出来 | `nvram_safe_set(v9, v)` | 记 `unrecovered` + 原因 |

> **不要用「占位键」蒙过去。** 键恢复失败时必须显式记 `key-unrecovered`（G7 判失败），因为两个拼不出来的人很可能拼出**不同的错键**，"看起来配上了"比"明显没配上"更危险。

## 5. IPC 是「数据」还是「控制」：两个约束

一个键既可能只是存数据，也可能是**驱动控制流的事件**（`notify_rc("start_vlanall")` → rc 里跳进 `start_vlanall` 分支）。后者才是高阶链里"跨进程"那一段的来源。Bridge 用两条启发式区分：

**① 消息生产 - 集中性约束**

- 多个 action handler 写**同一个** IPC 接口（同一 nvram 键 / 同一 `IP:port` / 同一文件路径）→ 更像系统级控制，而不是业务数据。
- 实现是**计数 + 双阈值**（artifact 常量 `nvram_IPC_threshold = 10` / `socket` / `fileloc` 同为 10）：

  ```
  统计每个 (键) 被多少个不同 action 写过 → top = 最大计数
  若 top <= 10：判定该类无控制 IPC，直接放弃
  相对阈值 interval = find_interval(top)      # 取 top 所在 2 的幂区间的下界一半
  候选 = 计数 > interval 的键                   # 再排一次序
  ```

  `find_interval`：`5→2, 12→4, 100→32, 1000→256`。即**同时要求绝对和相对两个门槛**，避免"只有一个键特别热"时把所有键都判成控制。

**② 消息消费 - 控制流约束**

- 对消息消费者做污点分析：**消息是否影响分支条件/比较函数**（控制依赖）。传不到控制位置 → 只是数据。
- 对带参数的进程调用同样适用（`system(cmd)` 的 `cmd` 若来自某个键，该键就是控制消息）。

## 6. 阶段三：ADG（跨进程控制流）

ADG 的节点是 `(二进制, 接口类型, action_key)`，边是控制转移。构建顺序：

1. **跨库调用图**：先为每个二进制建 CG，**递归解析库函数调用直到 libc 层**（因为 IPC 原语常被第三方库包一层，直接查导入表会漏）。
2. **IPC 分析**：在 CG 上找 IPC 调用点，向上回溯调用路径，聚合成"某函数在某上下文中发起了什么控制消息"。
3. **三类控制依赖**（artifact 实测数量 509 / 2346 / 677）：

| 类型 | 判据 | 控制值从哪来 |
|---|---|---|
| **隐式 IPC** | 写端在多个 action 里复用同一键；读端按值分发到不同 handler | 欠约束符号执行（§7） |
| **进程调用** | 显式：命令串首个词就是目标程序 | 调用点实参；含 shell 脚本时用 **AST**（bashlex + BashCFG）解析 |
| **信号** | `kill`/`raise` + 信号号 | 直接配对 `signal`/`sigaction` 注册的处理函数 |

**显式 vs 隐式的处理差别**：

- **显式**（`system("sysctl -p 14")`、`kill(pid, SIGUSR1)`）：控制值就在参数里，定位调用点取实参即可。难的是**命令串里套 shell 脚本**——脚本里的变量赋值、条件分支会让"到底执行了哪个二进制"无法用正则看出，必须上 AST/CFG。
- **隐式**（`notify_rc(service)`、`sendto(...,"start_vlanall")`）：控制值可能在运行时拼出来。做法是**只对相关基本块做欠约束定向符号执行**：先用反向数据依赖分析找出"通往根节点的可达基本块"，再只在那些块上跑 SE，避免全路径探索。

**控制值 → handler 的解析（两种 handler）**：

| handler 类型 | 场景 | 解析方式 |
|---|---|---|
| **固定** | 信号 | 信号号直接匹配 `signal/sigaction` 注册表，无需推断 |
| **灵活** | 隐式 IPC 值、进程调用参数 | 把 `argv` / `recvfrom` 当污点源，符号执行推导该值在各路径的取值，**其影响的分支入口之后的受影响基本块**即该值对应的 handler |

**终止条件**（`_judge_is_end`）：一个二进制若**不导入任何 IPC 原语**，且它依赖的库展开后也到不了 IPC 原语，则它是链路终点，不再向下扩展。这一步是防止 ADG 无限膨胀的关键。

## 7. 欠约束符号执行：参数与坑

`IPC_SE` 子工程（angr）负责"这个 IPC 值到底会跳到哪个 handler"。

| 参数 | 实测值 | 说明 |
|---|---|---|
| 状态 | `UNDER_CONSTRAINED_SYMEXEC` + `LAZY_SOLVES` | 从函数中间起跑，不要求完整调用栈 |
| 起点 | **比较之后的分支入口** `entry_addr` | 不是函数入口；MIPS 还要把 `t9` 设成函数地址、跳过 prologue |
| 返回哨兵 | `0x41414141` | 命中即视为该路径结束 |
| 循环上限 | **2 次** | 同一循环指令命中 ≥ 2 即杀状态 |
| 单次超时 | **600 s**（role 推断 60 s） | **超时即清空结果**，不得用部分块集充当完整 handler |
| 地址具体化 | `NorepeatsRange(min=0x400, granularity=0x400)` | 防止符号地址反复读到同一处 |
| 字符串读取上限 | 256 字节 | 与常量恢复一致 |

**输出格式**（`IPC_SE/result/*.json`，实测）：

```json
// <fw>_<binary>_<mech>_getter_content_info.json —— 控制值 → handler 块集合
{"4199544": [4199544, 4199608, ...], "4223444": [...]}

// <fw>_<binary>_socket_getter_role_info.json —— socket 角色
["0.0.0.0", 9930]
```

> **实践提醒**：这套东西的代价是真实的——Bridge 全量 44 个固件平均 **3.06 小时/固件**，需要 IDA Pro + angr + 40 核并行。没有这些条件时，正确做法是**降级到静态近似并明确标注置信度**，不是假装跑过。

## 8. 隐式流（implicit flow）

除了显式赋值，值还会通过**控制依赖**泄漏：`if (nvram_get("x") == 1) system("reboot")` 里，`x` 没有流进 `system` 的实参，但它决定了执行哪条命令。Bridge 在污点引擎里单独处理了隐式流（artifact 的 `data_trace` / `security_check` 有对应约束记录）。

对审计的要求很实际：**当 Source 只影响"走哪条分支"而不影响实参时，不要因为「实参是常量」就判 NOT_FOUND**。要写明「控制流受污点影响，触发条件为 `x == <值>`」。

## 9. 产物 → 门禁：`taint-graph.json` 与 G7

`scripts/taint_graph.py` 把上面的结论固定成图，`coverage_gate.py --taint-graph` 按 §0 的 C1–C4 否决。

```bash
# 1) 从反编译产物恢复常量键，得到 facts 骨架
uv run scripts/taint_graph.py recover --src fw-audit/<t>/decomp \
    --out fw-audit/<t>/taint-facts.json --target <t>

# 2) 人工/AI 补齐读写点与 sink（recover 会标 sink_candidates 指方向）
# 3) 构图 + 自检
uv run scripts/taint_graph.py build --facts fw-audit/<t>/taint-facts.json \
    --out fw-audit/<t>/taint-graph.json --md fw-audit/<t>/taint-graph.md --strict

# 4) 门禁（strict 下若报告声称了高阶漏洞，本项为必需）
uv run scripts/coverage_gate.py --profile strict ... \
    --taint-graph fw-audit/<t>/taint-graph.json
```

facts 的最小形状：

```json
{"schema":"taint-facts/1.0","target":"DIR878","store_type":"nvram_0",
 "actions":[
  {"id":"SetNetworkSettings","binary":"prog.cgi",
   "writes":[{"key":"lan0_management_link","func":"nvram_safe_set","addr":"0x43b57c",
              "value_from":"DeviceName","evidence":"prog.cgi:0x43b57c nvram_safe_set(...)"}]},
  {"id":"SetRouterLanSettings","binary":"prog.cgi",
   "reads":[{"key":"lan0_management_link","func":"nvram_safe_get","addr":"0x430d1c",
             "evidence":"...","sink":{"name":"system","addr":"0x4312cc"}}],
   "ipc_control":[{"func":"notify_rc","value":"start_vlanall",
                   "target_action":"restart_lan","target_binary":"rc","evidence":"..."}]}]}
```

门禁判据（G7，任一不满足即失败）：

1. 每条链 `write.action ≠ read.action` 或 `write.binary ≠ read.binary`（**C1**）；相同则必须降级到 `first_order`。
2. 写端键与读端键**字面一致**（**C2**）。
3. `write`/`read` 各有 `addr` 与 `evidence`；`sink.kind` 必须归入已知类型（**C4**）。
4. `defects` 中不得有 `key-unrecovered`（**C2** 未闭合）。
5. 报告声称了高阶漏洞时，图中**必须存在**高阶链（只有结论没有图 = 失败）。

> G6 与 G7 的分工：**G6 查"报告文字有没有写写入面"，G7 查"这条链在图里成不成立"。** 二者不互相替代——文字可以含糊，图不能。

## 10. 没有 IDA / angr 时的降级路径

| 能力 | 有 | 没有 |
|---|---|---|
| AEH 识别 | IDA 反编译 + 上述算法 | 用 `radare2`/`ghidra` 导出交叉引用与 .data 段，人工套 §2 的模式；三模式里至少能可靠做到「注册回调」和「函数指针表」 |
| 键恢复 | OD-ICP / SE | `taint_graph.py recover` 的四条规则 + 人工读伪代码；恢复不了的**必须记 unknown** |
| handler 定界 | 符号执行 | 用比较链的可达块集近似（§2.2），置信度降为 **HYPOTHESIS** |
| socket 角色 | SE 恢复 `IP:port` | 读初始化脚本 / `netstat` 基线 / 配置里的默认端口，标 `inferred` |

**降级不是可耻的事，含糊才是。** 凡是没做到 C1–C4 的，一律写成 `HYPOTHESIS` 并说明缺哪一环——`vuln-conditions.md` 的成立条件表就是为此存在的。

## 11. 已知边界（照抄会踩的坑）

1. **`nvram_set` 参数顺序随厂商变化**：`nvram_0` = `(key, value)`，`nvram_1` = `(index, key, value)`。配错参数位置 → 键变成随机值，配对全废。`apmib_set` 的键是**整型 id**，只能按 id + 偏移配对，不能按字符串。
2. **静态配置不算写面**：镜像里 `.conf`/`.cfg` 的默认值不是运行时写入（G6 已排除）。把默认值当写面会把所有配置项都报成高阶。
3. **`snprintf` 不是安全牌**：截断后若仍按原长度处理/拷贝，照溢。Bridge 的 `weak_copy` 会连长度约束一起算。
4. **共享库里的 IPC 原语**：只查二进制的导入表会漏（`.so` 里包了一层）。必须先建跨库 CG。
5. **超时/失败的结果不能用**：SE 超时返回空集，与"真的没有分支"不可区分——必须显式区分"空结果"和"执行失败"。
6. **同一 action 读写同一键很常见**（先写后读回显）。这类是**一阶**，不要为了凑"高阶"数字把它们算进去。

## 12. 参考

- 论文：IEEE S&P 2026, pp. 3320–3339（`conf/sp/PengLZCLYZ26`）
- Artifact：<https://zenodo.org/records/17232400>（`10.5281/zenodo.17232400`，14.3 GB，含 44 个固件）
- 本文对照的源码（镜像内路径）：`/home/action_transfer_paper.py`、`/home/action_handler_infer.py`、`/home/arg_parse.py`、`/home/bash_parse.py`、`/home/dataflow/security_check.py`、`/IPC_SE/*`
- 词表：`assets/ipc-functions.json`（IPC 原语 / sink / IPF / 阈值，均取自上述代码）
- 门禁：`scripts/coverage_gate.py`（G6 文字判据、G7 图判据）
