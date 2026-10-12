# 漏洞成立条件判断表（固件版）

> **用途**：Layer 3 验证与 Phase 4 之间。发现一个「危险调用」或「疑似缺失的控制」之后，**不要直接下结论**，先按本表逐条排除条件。任何一条不满足 ⇒ 降到 `HYPOTHESIS`。
>
> **为什么不直接报**：固件里 `system()`、`strcpy()` 遍地都是——工具一扫几百条。**「危险调用的存在」和「漏洞的成立」之间隔着 N 个条件**。本表就是把「还差什么」显式化。
>
> 这与 `references/vuln-taxonomy.md` 互补：taxonomy 管「去哪些攻击面找」，本表管「找到之后怎么判定成立」。

## 0. 通用四问（每个候选都必须过）

不管什么漏洞类型，先过这四问。任一为「否/未知」⇒ `HYPOTHESIS`。

| # | 问题 | 否定的后果 | 怎么查 |
|---|---|---|---|
| Q1 | **代码存在吗？** 该功能/函数真被编译进固件了吗（不是被裁剪/未启用）？ | 整个候选作废 | 字符串/符号/反汇编里定位该函数本体；不是只看版本号 |
| Q2 | **可达吗？** 从外部入口真能走到这条路径（不是死代码/调试残留）？ | 降 `HYPOTHESIS` | 从入口（Web handler / socket recv / ioctl / 文件解析）正向溯源，或从 sink 反向追到入口 |
| Q3 | **输入可控吗？** 参数真由外部输入决定，且未被过滤/限长？ | 降 `HYPOTHESIS` | 追参数来源；查有无 `strncpy`/白名单/长度检查 |
| Q4 | **防护状态如何？** 运行时缓解措施（NX / Canary / ASLR / PIE / RELRO / FORTIFY）对该利用路径是否构成实际阻断？ | 影响可利用性评级 | `checksec` 类画像；`fw_triage.py` 已产出 |

**这四问对应 `methodology.md` §4 的「禁止清单」**：四问全「是」才有资格谈 `CONFIRMED`。

---

## 1. 命令注入 / 命令执行（`system` / `popen` / `execve` / shell 反引号）

固件最高频漏洞类型，也最容易误报——**字符串拼接进 `system()` ≠ 命令注入**。

```
发现 system(cmd) / popen(cmd) / execve(...) / CGI 里反引号
  ↓
① cmd 是常量串吗？
   是 → 不是注入（除非串本身含 %s 且被 sprintf 填充，回到 ①'）
  ↓ 否
①' 是格式化拼接（sprintf/snprintf/asprintf）吗？
   是 → 记录格式串 + 参数来源；转 ②
   否（cmd 本身就是变量）→ 转 ②
  ↓
② 参数来源是什么？
   nvram_get("...")        → 转 ③（NVRAM 可控 → 等价外部可控）
   HTTP 请求字段 / query   → 外部可控 ✔
   UDP/TCP 收到的报文       → 外部可控 ✔
   硬编码路径 / 常量         → 不可控，降 HYPOTHESIS 或排除
  ↓
③ 参数是否被过滤 / 转义？
   有 shell 元字符过滤（| & ; $ ` > < \n 等）   → 降 HYPOTHESIS（可能绕，但要证明）
   有白名单校验                                → 降 HYPOTHESIS
   无过滤 / 只做了长度截断                      → ✔ 继续
  ↓
④ 认证状态？
   入口无需认证（预认证）          → CRITICAL 方向
   需认证但存在默认口令 / 越权     → 仍成立，评级下调或不调（视默认口令是否出厂）
   需认证且无绕过                 → 降级
  ↓
⑤ 动态确认（Phase 4）
   Qiling hook system() 看参数真值；或真机发 payload 观察命令执行副作用
```

**关键检查（bash 一行式）**：

```bash
# 定位命令执行 sink（二进制）
for f in $(fd -t f . rootfs -e so -H); do
  nm -D --undefined-only "$f" 2>/dev/null | rg -q 'system|popen|execve|execvp' \
    && echo "== $f" && nm -D --undefined-only "$f" | rg 'system|popen|exec'
done

# CGI / shell 脚本里的注入面
rg -n --pcre2 '`[^`]*\$|system\s*\(|\$\((.*)\)|eval ' rootfs/www rootfs/etc --glob '*.cgi' --glob '*.sh'

# NVRAM 取值后的拼接（固件特有的「隐式外部可控」）
rg -n --pcre2 '(nvram_get|nvram_safe_get|acos_nvram_get)\s*\([^)]*\)[^;]*(sprintf|strcat|snprintf|system)' rootfs -g '*.c' 2>/dev/null
```

**误报陷阱**：
- `system("ifconfig eth0 down")` —— 常量，无注入。
- `system(cmd)` 但 `cmd` 来自编译常量表 —— 无注入。
- `snprintf(buf, ..., "ping -c 1 %s", ip)` 且 `ip` 来自 NVRAM —— **是注入**，NVRAM 可通过 Web/SNMP 写（需追 NVRAM 本身的可写入口，这是固件特有的第二跳）。
- `popen("ls /tmp", "r")` —— 常量，不是注入。

---

## 2. 栈/堆溢出（`strcpy` / `strcat` / `sprintf` / `memcpy` / 数组下标）

```
发现无边界拷贝
  ↓
① 目标缓冲区大小固定吗？源长度可控吗？
   源有长度上限（如 recv 到 256 字节 buf，拷进 4096 数组）  → 不溢出
   源长度 ≥ 目标容量且无检查                          → 溢出 ✔
  ↓
② 触发路径可达吗？（Q2）从哪个入口进？
       ↓
③ 运行时防护（Q4）
   - 有 Stack Canary 且路径经过函数返回 → 溢出到返回地址会先触发 __stack_chk_fail
     → 仍是有漏洞（可泄 canary / 改 GOT / 覆盖局部变量），但评级下调
   - NX 关闭 → 可跳 shellcode，评级上调
   - PIE 关闭 → 固定地址，ROP/ret2libc 更容易
   - FORTIFY_SOURCE → `__strcpy_chk` 会在编译期/运行期拦截已知目标的溢出
     → 若目标大小已知且源可静态分析，溢出被拦 → 降级
  ↓
④ 可控数据的边界？溢出能覆盖到哪些关键数据？
   - 溢出长度受限于协议帧长 → 算清能覆盖多少字节
   - 覆盖到函数指针 / 返回地址 / GOT / vtable → 可控执行流
```

**关键检查**：

```bash
# 定位无边界拷贝 + 关联的缓冲区声明
rg -n --pcre2 '\b(strcpy|strcat|sprintf|gets|memcpy)\s*\(' rootfs -g '*.c' -g '*.cpp'
# 二进制侧：符号 + 反汇编确认
r2 -A -q -c 'aaa; axt @ sym.imp.strcpy' rootfs/usr/sbin/httpd
# 缓解措施画像
readelf -hW rootfs/usr/sbin/httpd | rg 'Type'          # PIE?
readelf -dW rootfs/usr/sbin/httpd | rg 'BIND_NOW|FLAGS' # RELRO?
nm -D --undefined-only rootfs/usr/sbin/httpd | rg '__stack_chk_fail|__strcpy_chk'
```

**误报陷阱**：
- `strcpy(dst, "literal")` —— 常量源，不溢出。
- `strcpy(dst, src)` 但 `src` 是固定长度表 —— 需证明可控性。
- `sprintf(buf, "%d", intval)` —— 格式化输出长度有界（int 最多 11 字符）。
- **FORTIFY 会拦**：`__strcpy_chk(dst, src, __bos(dst))` —— 目标大小编译期已知时运行期 aborts，不再是可利用溢出（但仍算健壮性缺陷）。

---

## 3. 认证绕过 / 鉴权缺失

这类漏洞**工具看不见**（「本该有却没有」），只能 Track B 发现。判定关键在**入口矩阵**。

```
发现 Web handler / API 路由 / CGI
  ↓
① 枚举全部入口，做「认证矩阵」
   把每个 URL/action 分成：无需认证 / 需认证 / 需管理员
   逐行标注「该行有没有鉴权检查」
  ↓
② 有没有预认证可达的敏感操作？
   - 直接跳转到功能 handler 而不经过 auth 检查 → 绕过
   - auth 检查在功能之后（顺序错误）→ 绕过
   - 大小写/路径变体绕过（/admin vs /ADMIN、/%61dmin、/admin/..;/）→ 绕过
  ↓
③ 鉴权是「检查存在」还是「检查每次都做」？
   - 只在登录页检查，功能页信任 session → session 伪造 / 固定
   - token 可预测（时间戳/递增 ID）→ 伪造
  ↓
④ 默认口令
   - 出厂默认且不改也放行 → 等于预认证可达（评级按预认证算）
  ↓
⑤ 动态确认：真机/模拟发请求，看能否不登录到达功能页
```

**关键检查**：

```bash
# 定位所有路由注册与 handler 分发
rg -n --pcre2 '(httpd_register|websGetVar|websSetVar|do_|handle_.*_request|route|dispatch)' rootfs/www rootfs/usr/sbin -g '*.c' -g '*.cpp' 2>/dev/null
# CGI 清单（每个都是一个入口）
fd -t f . rootfs/www -e cgi && fd -t f . rootfs/www/cgi-bin
# 找 auth 检查函数，看它在哪些入口被调用
r2 -A -q -c 'aaa; afl~auth; afl~login; afl~check' rootfs/usr/sbin/httpd
```

**误报陷阱**：
- 有 auth 中间件但某一条路由挂在中间件之前 ⇒ 才是绕过；只是「代码里有个没被调用的 auth 函数」不算。
- 检查 auth 但存在默认口令 ⇒ 仍算绕过（默认口令是出厂事实）。
- 前端做了校验但后端没有 ⇒ 是绕过（前端可绕）。

---

## 4. SSRF（服务端请求伪造）

```
发现 http request / curl / wget / socket connect 以外部输入为 URL/Host
  ↓
① 目标地址由外部输入决定吗？
   是 URL 参数 / 表单字段         → 可控 ✔
   是常量 / 配置里的固定地址        → 不可控
  ↓
② 有没有目标限制？
   白名单域名/IP 段            → 需证明绕过（DNS rebinding / 30x 跳转 / IPv6 变体）
   只挡了 http:// 没挡 file:// gopher:// dict:// → 协议走私
   无限制                     → ✔
  ↓
③ 回显吗？（决定危害）
   有回显（把响应内容返回）  → 可探测内网服务、读云元数据
   无回显                  → 只能盲打（时间侧信道 / DNS 外带）
  ↓
④ 可达的内网资产
   云元数据 169.254.169.254 / 内网管理口 / 本地环回服务（如本机 127.0.0.1:8080 管理接口）
```

**关键检查**：

```bash
rg -n --pcre2 '(curl_easy_setopt|CURLOPT_URL|http_get|http_request|wget )' rootfs -g '*.c' -g '*.sh' 2>/dev/null
rg -n --pcre2 '(popen|system)\s*\([^)]*(wget|curl|tftp|ftpget)' rootfs -g '*.c' -g '*.sh' 2>/dev/null
```

---

## 5. 文件上传 / 路径穿越 / 任意写

```
发现 file 写 / unlink / rename / open(O_CREAT) / fopen(w)
  ↓
① 路径由外部输入拼接吗？（含文件名）
  ↓
② 是否有 ../ 过滤？
   无过滤 / 只过滤了字面 "../"（可被 ....// 、%2e%2e 绕过）  → 穿越 ✔
   规范化后再校验（realpath + 前缀检查）                  → 挡住了
  ↓
③ 落点可控到什么程度？
   可写 /etc/ 启动脚本 → 持久化 + 重启后执行（严重）
   可写 Web 根目录      → webshell（若 Web 支持 CGI/脚本执行）
   可写 /tmp 且该文件会被 root 进程执行 → 提权链一环
  ↓
④ 上传内容可控吗？有没有扩展名/内容校验？
   无校验 + 目录可执行 → webshell
   只校验扩展名        → 试 .phtml/.php5/.phar/大小写/双扩展名
  ↓
⑤ 权限：写操作以什么身份跑？root 还是 nobody？
```

**关键检查**：

```bash
rg -n --pcre2 '(fopen|open)\s*\([^)]*"w|O_CREAT|rename\s*\(|unlink\s*\(' rootfs/www rootfs/usr/sbin -g '*.c' -g '*.cgi' 2>/dev/null
# 上传目标目录是否可执行（决定能否 rce）
ls -la rootfs/www/  # CGI 目录、cgi-bin 存在与否
```

---

## 6. 固件升级 / OTA 无验签（IoT 特有高价值）

这是固件领域**最影响量产的漏洞类型**——一旦可刷任意固件，等于设备永久沦陷。

```
发现升级流程（upload / tftp / http 拉取 / USB / OTA）
  ↓
① 固件包从哪来？网络拉取 / 上传？
  ↓
② 有没有签名/校验？
   无签名校验                          → ✔ 可刷任意固件
   有校验但是弱校验（CRC32/MD5，且 key 在固件里）→ 等于无（可重算）
   有 RSA 签名但公钥在固件里可改        → 换公钥即绕过
   RSA/ECDSA 签名 + 公钥锁定（不可改）  → 挡住了，降级
  ↓
③ 校验在解包前还是解包后？
   解包后才校验 → 解析器已吃了恶意输入（parser 漏洞链）
   解包前校验但解析用同一个不可信输入 → 仍可能解析器漏洞
  ↓
④ 升级包格式解析器是否有内存破坏面？（叠加 §2）
  ↓
⑤ 是否降级保护？（能否刷入旧版有漏洞固件 → 变相绕过修复）
```

**关键检查**：

```bash
rg -n --pcre2 '(upgrade|firmware|ota|flash_erase|mtd_write|write_firmware)' rootfs/www rootfs/usr/sbin rootfs/etc -g '*.c' -g '*.sh' -g '*.cgi' 2>/dev/null
rg -n --pcre2 '(rsa_verify|verify_signature|check_sign|sha256|md5|aes_decrypt)' rootfs -g '*.c' 2>/dev/null
# 找升级相关的 handler 与它调用的校验函数
r2 -A -q -c 'aaa; afl~upgrade; afl~firmware; afl~verify' rootfs/usr/sbin/httpd
strings -a rootfs/usr/sbin/httpd | rg -i 'firmware|upgrade|signature|verify|\.bin|mtd'
```

---

## 7. MQTT / 云对接鉴权缺失（IoT 特有）

```
发现 MQTT 客户端 / 云 API 调用
  ↓
① 连接用凭证吗？还是匿名？
   匿名（anonymous）或固定硬编码凭证 → 同一产品所有设备通用 → 大规模影响
  ↓
② 硬编码凭证在固件里可提取吗？（strings 直接可见？还是加密的？）
  ↓
③ Topic 是否有 ACL？能否订阅他人设备的 topic（如 cmd/<other_id>）？
  ↓
④ Broker 是否校验 client_id 与设备身份绑定？（否则可冒充任意设备）
  ↓
⑤ 下发指令是否有签名/新鲜度校验？（否则可重放）
```

**关键检查**：

```bash
strings -a rootfs/usr/sbin/* 2>/dev/null | rg -i 'mqtt|broker|amqp|tls://|ssl://'
rg -n --pcre2 '(mqtt_connect|MQTTClient_connect|IOT_Connect|user_pass|client_id)' rootfs -g '*.c' 2>/dev/null
# 硬编码凭证
rg -n --pcre2 '(password|passwd|psk|secret|token)\s*=\s*"[^"]{4,}"' rootfs -g '*.c' -g '*.sh' -g '*.conf' 2>/dev/null
```

---

## 8. 反序列化（固件里的少见但致命）

```
发现反序列化调用（fastjson/Jackson/PHP unserialize/Python pickle/Java readObject）
  ↓
① 用了哪个库、什么版本？（版本决定 autotype 默认状态）
  ↓
② 反序列化入口可达吗？（网络接收字节 → 反序列化是最危险形态）
  ↓
③ 有没有类型白名单 / safeMode？
  ↓
④ classpath / 固件里有没有可用 gadget？
   没有 gadget → 不可利用（降级）
   → 需要做 gadget 链搜索，不是看版本就报
```

**关键检查**：

```bash
rg -n --pcre2 '(JSON\.parseObject|readObject|unserialize|pickle\.loads|yaml\.load)' rootfs -g '*.c' -g '*.php' -g '*.js' 2>/dev/null
# Java 组件（若固件含 Java 运行时）
fd -t f . rootfs -e jar
```

---

## 9. 弱随机 / 弱密钥 / 硬编码（「严重程度取决于用途」）

```
发现 rand() / srand(time) / 固定 key / 固定 salt
  ↓
① 这个随机数用在哪？
   session token / 加密密钥 / 重置密码 token → 严重（可预测 ⇒ 可伪造）
   非安全用途（统计/UI）→ 不是漏洞
  ↓
② 硬编码密钥是**对称密钥**吗？
   对称密钥在固件里 ⇒ 所有同型号设备共用 ⇒ 一个设备被解，全型号沦陷
   公钥在固件里 ⇒ 通常没问题（除非可被替换，见 §6）
  ↓
③ 密钥能否被提取？strings 直接可见 / 需要解密一个固定 key？
```

---

## 10. 前后端校验错位 / 业务逻辑（工具必漏）

```
发现前端 JS 做校验、后端信任前端
  ↓
① 后端有没有重复校验？
   只在前端校验 ⇒ 绕过前端即可（改请求）→ 漏洞
  ↓
② 状态机可跳步吗？（如下单→支付→发货 能否跳过支付）
  ↓
③ 竞态：检查与使用之间有时间窗吗？（TOCTOU）
   典型：先检查文件是否存在，再打开 —— 中间可替换（符号链接攻击）
  ↓
④ 数量/金额可为负？边界值？
```

**关键检查**：

```bash
rg -n --pcre2 '(eval|new Function|innerHTML)' rootfs/www -g '*.js' 2>/dev/null
# 前端校验函数 vs 后端同名校验 —— 看后端是否也存在
```

---

## 附：判定表速查（把候选变结论的检查单）

对每个候选填这张表。**任一「否/未知」列 ⇒ `HYPOTHESIS`**：

| 项 | 结论 | 依据（`文件:偏移` 或命令输出） |
|---|---|---|
| Q1 代码存在 | 是 / 否 | |
| Q2 路径可达 | 是 / 否 / 未知 | 入口 = ? |
| Q3 输入可控 | 是 / 否 / 未知 | 来源 = ? 过滤 = ? |
| Q4 防护阻断 | 无 / 有(哪项) / 未知 | NX=? Canary=? PIE=? RELRO=? |
| 类型专属条件 | … | 见对应小节 |
| 动态确认 | 已复现 / 未做 / 不可做 | 方法 = ? |

**全绿 ⇒ `CONFIRMED`；任一红/未知 ⇒ `HYPOTHESIS` + 写明「缺哪一步」。**

---

## 附：与工具输出的衔接

| 工具输出 | 对应本表哪一节 | 注意 |
|---|---|---|
| `sink_scan.py` P0 命中（`system`/`strcpy`） | §1 / §2 | 是**候选**，不是漏洞——必须过四问 |
| `mithril --cve` 组件命中 | §8 / 各节 Q1 | 先看 Q1「代码存在吗」，不存在直接作废 |
| `fat taint` 污点结果 | §1 / §2 / §5 | 污点「可达」≠「可控且未过滤」，仍需 §中过滤检查 |
| `checksec` / `fw_triage.py` 加固画像 | Q4 | 只影响**评级**，不影响「是不是漏洞」 |
| Layer 1 P1（认证/OTA/SSL 线索） | §3 / §6 | 正是工具看不见的类别，必须 Track B 人工核 |
