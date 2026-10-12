# 静态扫描模式库（sink patterns）

本文件说明 Layer 1 的规则体系，并给出**手写 grep / YARA / radare2 规则**的模板。实际规则库在 `assets/sink-rules.json`，由 `scripts/sink_scan.py` 消费。

## 1. 规则文件 schema

```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "P0-C-001",
      "priority": "P0",              // P0 | P1 | P2 | P3
      "category": "cmd-exec",        // 分类，用于聚合统计
      "title": "命令执行接口",
      "applies_to": ["binary", "text"],   // binary | text | script | web | config
      "patterns": ["\\bsystem\\s*\\("],   // Python re，任一命中即算
      "anti": ["system\\s*\\(\\s*\"[^\"]*\"\\s*\\)"],  // 命中即排除（降噪）
      "guidance": "向上追参数来源，确认是否外部可控、是否过滤、是否需认证"
    }
  ]
}
```

**文件类型判定**（scanner 内部）：

| 类型 | 判据 |
|---|---|
| `binary` | 含 ELF/PE/Mach-O/`0x7fELF` magic，或含大量不可打印字节 |
| `script` | 扩展名 `.sh/.bash/.cgi/.pl/.py/.lua` 或首行有 shebang |
| `web` | `.html/.htm/.js/.php/.asp/.jsp/.json(页面态)` |
| `config` | `.conf/.cfg/.ini/.xml/.properties`、`nvram`、`default.cfg` |
| `text` | 其余可解码为 UTF-8/ASCII 的文件 |

`binary` 的处理方式：提取长度 ≥4 的 ASCII 字符串（等价 `strings -a -n 4`），在字符串上跑模式，命中记为 `kind: "binary-string"`。**不声称「代码里调用了 system」，只声称「二进制里出现了该字符串」**——代码层结论必须交给 Layer 3 反汇编。

## 2. P0 规则（命令执行 / 内存破坏 / 高权限操作）

### 二进制专用规则（**必须单独一套**）

**关键坑**：剥离符号的 ELF 里，`.dynstr` / `.dynsym` 中只有**裸符号名**（`system`、`strcpy`），没有括号。如果二进制也套用源码规则（`system\s*\(`），会**系统性漏检所有通过 PLT 调用的场景**——而这正是固件里最常见的形态。因此二进制单独一套规则，不要求括号：

| ID | 模式 | 说明 |
|---|---|---|
| P0-B-001 | `\bsystem\b`、`\bpopen\b`、`\bexecl[pe]?\b`、`\bexecvp?\b`、`\bposix_spawn\w*\b`、`\bvfork\b` | 命令执行符号被引用 |
| P0-B-010 | `\bstrcpy\b`、`\bstrcat\b`、`\bsprintf\b`、`\bgets\b`、`\bsscanf\b`、`\bmemcpy\b`、`\bmemmove\b`、`\balloca\b`、`\bvsprintf\b` | 无边界内存操作符号 |
| P2-B-030 | `\bsrand\b`、`\bsrandom\b`、`\brand\b`、`\brandom\b` | 弱随机符号 |

**措辞纪律**：二进制命中只表示「该符号被引用（导入或定义）」，**不等于**「代码里调用了它并传了用户输入」。报告与候选里必须写成 `binary-string`，代码层结论（调用点、参数来源）交给 Layer 3 反汇编。这是本 skill 反幻觉规则在扫描层的落地。

### 命令执行

| ID | 模式 | 说明 |
|---|---|---|
| P0-C-001 | `\bsystem\s*\(`、`\bpopen\s*\(`、`\bexecl[pe]?\s*\(`、`\bexecvp?\s*\(`、`\bposix_spawn\w*\s*\(`、`\bvfork\s*\(` | C 系命令执行 |
| P0-S-001 | `` ` ``、`\$\(`、`\beval\b`、`\bexec\b`、`\bsource\s+/`、未引号 `\$[A-Za-z_]\w*` 紧跟 `;`/`\|` | shell 命令注入面 |
| P0-W-001 | `\bsystem\s*\(`、`\bexec\s*\(`、`\bshell_exec\s*\(`、`\bpassthru\s*\(`、`\bproc_open\s*\(`、`\bpopen\s*\(`、`\bassert\s*\(\s*\$`、`preg_replace\s*\(.*/e` | PHP/CGI |
| P0-J-001 | `\beval\s*\(`、`\bFunction\s*\(`、`document\.write\s*\(`、`\.innerHTML\s*=`、`setTimeout\s*\(\s*['"]` | 前端 JS |
| P0-C-002 | 高危业务命令串：`ping -c`、`traceroute`、`nslookup`、`wget `、`curl `、`iptables`、`nvram set`、`tar `、`dd if=`、`insmod`、`modprobe`、`reboot`、`killall`、`mtd write`、`flash_erase` | 出现即优先追参数来源 |

### 内存破坏

| ID | 模式 |
|---|---|
| P0-C-010 | 无界拷贝：`\bstrcpy\s*\(`、`\bstrcat\s*\(`、`\bsprintf\s*\(`、`\bgets\s*\(`、`\bscanf\s*\(`、`\bsscanf\s*\(`、`\bmemcpy\s*\(`、`\bmemmove\s*\(`、`\balloca\s*\(`、`\bstrncpy\s*\(`（长度取 `strlen` 时等效无界） |
| P0-C-011 | 格式化字符串：`\bprintf\s*\(\s*[a-z_]\w*\s*\)`、`\bfprintf\s*\([^,]+,\s*[a-z_]\w*\s*\)`、`\bsyslog\s*\([^,]+,\s*[a-z_]\w*\s*\)` |
| P0-C-012 | 目录/路径拼接：`\bsprintf\s*\([^,]+,\s*"[^"]*%s[^"]*"` 且同文件有 `\bopen\s*\(`/`\bfopen\s*\(` |
| P0-C-013 | 高权限内核面：`/dev/mem`、`/dev/kmem`、`/proc/kcore`、`\bmmap\s*\(`、`\bioctl\s*\(`、`\bptrace\s*\(`、`insmod`、`\binit_module\s*\(` |
| P0-W-002 | 反序列化：`unserialize\s*\(`、`\bXMLDecoder\b`、`ObjectInputStream`、`yaml\.load\s*\(`（无 `SafeLoader`） |

## 3. P1 规则（安全控制缺失线索 / 弱校验）

| ID | 模式 | 说明 |
|---|---|---|
| P1-C-020 | `SSL_VERIFY_NONE`、`SSL_CTX_set_verify\s*\([^,]+,\s*SSL_VERIFY_NONE`、`CURLOPT_SSL_VERIFYPEER[^\n]*0`、`--insecure`、`verify\s*=\s*False` | TLS 不校验证书 |
| P1-C-021 | `\bstrcmp\s*\([^)]*pass`、`\bstrcmp\s*\([^)]*token`、`\bstrcmp\s*\([^)]*sig` | 时序侧信道（口令/签名比较） |
| P1-C-022 | `\bmd5\b`、`\bsha1\b` 用于完整性/口令：`md5\s*\(`、`MD5_Init`、`SHA1_Init` | 弱摘要 |
| P1-C-023 | 固定 salt/IV：`salt\s*=\s*"`、`iv\s*=\s*"`、`IV\s*=\s*\{` | 硬编码 salt/IV |
| P1-C-024 | OTA/升级 相关函数：`check_firmware`、`verify_firmware`、`upgrade_start`、`fw_update`、`flash_write`、`do_upgrade` | 定位后审计是否验签 |
| P1-C-025 | 认证相关：`check_auth`、`is_login`、`auth_check`、`session_verify`、`login_required` | 定位后审计覆盖是否完整（哪些路由绕过了） |
| P1-S-020 | `telnetd\s+-l\s+/bin/sh`、`telnetd` 无 `-l` 但 `passwd` 为空、`dropbear` 无 `-s` | 调试 shell |
| P1-S-021 | `chmod\s+777`、`chmod\s+-R\s+777`、`chown\s+root` 对可写路径 | 权限配置错误 |
| P1-G-020 | `PermitRootLogin\s+yes`、`PasswordAuthentication\s+yes`、`PermitEmptyPasswords\s+yes` | SSH 配置弱 |
| P1-G-021 | `\badmin\b.*\bpassword\b`、`default_passwd`、`factory_passwd`、`super_password`、`security_mode\s+off` | 默认口令/关闭安全模式 |
| P1-W-020 | 目录列举/调试页路由：`/cgi-bin/`、`/goform/`、`/api/`、`/debug`、`/dumpcfg`、`/backup`、`/upgrade`、`/hnap`、`/soap` | 入口枚举（配合 Track B 使用） |
| P1-W-021 | 鉴权中间件的路径白名单：`/images/`、`\.js$`、`\.css$` 出现在 `no_auth`/`skip_auth`/`whitelist` 上下文 | 认证绕过面 |

## 4. P2 规则（弱实现 / 硬编码 / 调试残留）

| ID | 模式 |
|---|---|
| P2-C-030 | 弱随机：`\brand\s*\(`、`\bsrand\s*\(\s*time`、`\brandom\s*\(`、`\btime\s*\(\s*NULL\s*\)\s*\)` 作为种子 |
| P2-C-031 | 硬编码密钥：`(KEY|SECRET|TOKEN|PASSWD|PASSWORD)\s*[:=]\s*"[^"]{4,}"`（排除占位符 `CHANGE_ME`/`xxx`/空串） |
| P2-C-032 | 调试开关：`debug\s*=\s*1`、`DEBUG_MODE`、`ENABLE_DEBUG`、`TEST_MODE`、`\bfprintf\s*\(\s*stderr` 大段输出 |
| P2-C-033 | 危险库使用：`\bgets\s*\(`（已在 P0）、`\btmpnam\s*\(`、`\bmktemp\s*\(`、`\baccess\s*\(` 用于权限判断（TOCTOU） |
| P2-C-034 | 命令拼接辅助：`\bsnprintf\s*\([^;]*"[^"]*%s[^"]*"[^;]*\)` 与 `system` 同文件 |
| P2-S-030 | `while\s+true` 无限循环无 sleep、`nc -l`、`socat` 监听、`busybox nc` |
| P2-G-030 | `password\s*=`、`passwd\s*=`、`secret\s*=`、`token\s*=`、`api_key\s*=`（配置文件明文） |

## 5. P3 规则（信息泄露面）

| ID | 模式 |
|---|---|
| P3-G-040 | 版本与构建信息：`GCC:\s*\(`、`\d+\.\d+\.\d+-\w+` 形如内核版本、`buildroot`、`OpenWrt`、`Copyright` 行 |
| P3-G-041 | 注释掉的敏感内容：`^\s*(#\|//\|<!--).*(password\|token\|key\|secret)` |
| P3-G-042 | 内嵌 URL/域名：`https?://[a-zA-Z0-9.\-]+`（用于云侧对接面枚举） |
| P3-W-040 | 前端泄露接口定义：`.js` 里的 `/api/`、`/cgi-bin/`、硬编码 token |
| P3-G-031 | 内部地址/调试地址：`192\.168\.\d+\.\d+`、`10\.\d+\.\d+\.\d+`、`127\.0\.0\.1:\d+`、`debug.*\.`（仅用于补全攻击面地图，本身不是缺陷） |

## 6. 降噪策略（必须生效）

1. **跳过 R0 目录**（见 `references/methodology.md`）
2. **anti 模式排除静态调用**：`system("ls")` 这类常量实参不报 P0-C-001（改报 P3 信息项）
3. **二进制只报字符串层命中**，`kind=binary-string`，并把优先级下调一档（P0→仍 P0，因为字符串出现在二进制里本身就是强线索；但结论措辞必须是「字符串存在」）
4. **同文件同规则只报首个命中 + 计数**（`count`），避免十万行日志把结果淹没
5. **跳过 `import`/`#include`/注释行**（源码类）
6. **±N 行上下文**（默认 2）写入 `evidence`，便于 Layer 3 直接接着看
7. **剥离符号的 ELF**：如果 `system`/`popen` 只出现在 `.dynstr`，说明是导入而非自实现，仍然报，但在 `note` 里注明「动态导入，需确认调用点」
8. **白名单文件**：`busybox` 本身、`libc.so`、`libcrypto.so`、`libssl.so`、`libpthread.so` 等标准组件默认降级到 P2（它们有 `system` 是正常的），可用 `--skip-stdlib` 开关控制

## 7. 手写一行式（工具缺失时的兜底）

**优先用 `rg` / `fd`**（见 `references/toolchain.md` §0.1）；下面同时给 `rg` 与 `grep` 两版，`grep` 版仅在 `rg` 缺失时使用。

```bash
# 命令执行面
rg -nE '\b(system|popen|exec[lv]p?e?)\s*\(' -t c -t cpp -t h
grep -rnE '\b(system|popen|exec[lv]p?e?)\s*\(' . --include='*.c' --include='*.cpp' --include='*.h'

rg -nE '`|\$\(|\beval\b' --glob '*.sh' --glob '*.cgi'
# 无界拷贝
rg -nE '\b(strcpy|strcat|sprintf|gets|memcpy|alloca)\s*\('
# 认证相关函数（用于 Track B 入口定位）
rg -nE '(check_|verify_|is_)(auth|login|session|token|permission|admin)'
# 升级流程
rg -niE '(upgrade|firmware|flash_write|verify)_?\w*' -g '*.c' -g '*.sh'
# 硬编码凭据
rg -niE '(passwd|password|pass|secret|token|api_?key)\s*[:=]\s*["'"'"'][^"'"'"']{3,}'
# 结构化搜索（ast-grep）：所有 system 调用及其实参，不受换行/格式影响
sg -p 'system($ARG)' -l c

# 二进制里的关键字符串（strings 输出后仍用 rg 过滤）
strings -a -n 5 usr/sbin/httpd | rg -iE 'referer|host|user-agent|cmd=|ping|upgrade'

# SUID / 可写（本机查文件用 fd；目标 rootfs 内仍需 find）
fd -t f -x sh -c 'test -u "$1" && echo "$1"' _ {}
find . -type f \( -perm -4000 -o -perm -2000 \) -ls
find . -type f -perm -0002 -ls
```

## 8. YARA 规则模板

用于在固件里批量识别**后门、被篡改的打包器、私有协议标记**。

```yara
rule UPX_zeroed_header
{
    meta:
        author = "iot-firmware-vuln-hunting"
        description = "UPX 头部被抹零以对抗 upx -d"
        source_finding = "F-0xx"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
    condition:
        // 出现 UPX 段名但缺少完整 PackHeader 校验位
        (any of ($upx*)) and filesize > 10KB
}

rule TelnetdNoAuthShell
{
    meta:
        description = "telnetd 直接挂 /bin/sh，无认证即 root shell"
    strings:
        $a = "telnetd -l /bin/sh" ascii wide
        $b = "/bin/sh" ascii
    condition:
        $a or ($b and filesize < 512KB)
}

rule HardcodedDefaultCred
{
    meta:
        description = "疑似通过固件内置默认口令绕过认证"
    strings:
        $p1 = "admin:admin" ascii
        $p2 = "root:root" ascii
        $p3 = "super_password" ascii
        $p4 = "default_passwd" ascii
    condition:
        any of them
}

rule PrivateProtoMagic
{
    meta:
        description = "私有协议魔数（按目标定制）"
    strings:
        $m = { 48 4E 41 50 }        // "HNAP"
    condition:
        $m
}
```

写规则的三条纪律：
1. 每条规则必须注明 `source_finding`（来源于哪个已确认漏洞），避免规则库变成无出处的猜测集合
2. 上线前用**已知干净固件**回归，确认误报率
3. 一条规则只描述一件事（不要在一个 rule 里塞 OR 逻辑的多种漏洞）

## 9. radare2 脚本片段（Layer 3 用）

```bash
# 列出所有对 system 的调用点
r2 -A -q -c 'aaa; axt @ sym.imp.system' usr/sbin/httpd
# 列出 strcpy 的交叉引用并反汇编调用者上下文
r2 -A -q -c 'aaa; axt @ sym.imp.strcpy; s <addr>; pd 20' usr/sbin/httpd
# 找字符串并反查引用
r2 -A -q -c 'aaa; izz~Referer; axt @ <str_addr>' usr/sbin/httpd
# 导出函数级调用图（用于人工追链）
r2 -A -q -c 'aaa; agC > /tmp/callgraph.dot' usr/sbin/httpd
# 批量：对所有导入的 system/popen 找调用点
r2 -A -q -c 'aaa; afl~main; axt @ sym.imp.popen' usr/sbin/httpd
```

结合 Qiling hook 把静态地址变成运行时事实：

```python
ql.hook_address(on_sink, 0x2a30)          # 在 Layer 3 定位的 sink 地址下 hook
ql.hook_code(on_every_insn)               # 指令级
ql.mem.read(addr, size)                   # 读内存看实参
ql.mem.string(ptr)                        # 读字符串实参
```

## 10. finding → 规则 的沉淀模板

Phase 5 把确认的漏洞转成规则时，按此格式追加到 `assets/sink-rules.json`：

```json
{
  "id": "P0-TPL-100",
  "priority": "P0",
  "category": "cmd-exec",
  "title": "TPL 系列 router 未认证 ping 命令注入",
  "applies_to": ["binary", "text"],
  "patterns": ["\\bping\\s+-c\\s+1\\s+%s", "\\bdo_ping\\b", "\\bcgi_ping\\b"],
  "anti": [],
  "guidance": "命中后直接查 /cgi-bin/ping 路由的鉴权分支；本模式来自 F-007",
  "source_finding": "F-007"
}
```
