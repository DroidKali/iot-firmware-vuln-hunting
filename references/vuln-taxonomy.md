# 固件漏洞分类学（按攻击面）

按攻击面组织的核查清单。每类给：**典型形成原因 / 静态特征 / 确认方法 / 优先级参考**。Track B（Control-driven）主要查这里的「缺失类」，Track A（Sink-driven）主要查「存在类」。

---

## 1. 凭据与身份

| 子类 | 静态特征 | 确认方法 |
|---|---|---|
| 硬编码口令 / 后门账号 | `strings` 出 `/etc/shadow` 条目、`admin:admin`、`root:root`、`support:support`、`debug` 账号、`default` 用户；`passwd` 里非标准 UID 0 账号 | 读 `etc/passwd` `etc/shadow`；`mithril --secrets`；登录验证（模拟环境） |
| 弱哈希 / 空口令 | shadow 里 DES 13 字符、`$1$`（MD5）、空哈希、`NP`/`*` 误用 | `john`/`hashcat` 离线跑；`mithril --secrets` 会标 weak-algorithm 与 empty-password |
| 硬编码云凭据 | AWS AK/SK（`AKIA…`）、阿里云 `LTAI…`、Azure connection string、Firebase `apiKey`、Google API key、微信/钉钉 token | `mithril --secrets`（pattern→structural→validated 阶梯）；**不要在线验证，用格式与校验和判定** |
| 私钥泄漏 | `-----BEGIN RSA PRIVATE KEY-----`、`*.pem`、`*.key`、`id_rsa`、设备 TLS 服务端私钥 | `mithril --keys`；判断是否全设备共用（固件里提取的私钥=全网同款） |
| 公钥弱点 | 默认/已知私钥泄露的公钥（rapid7 ssh-badkeys、Vagrant insecure key）、ROCA（CVE-2017-15361）、512/1024 位 RSA、Fermat 近素数、跨镜像共享素数、Wiener 小 d | `mithril --keys`（离线可证：指纹匹配 + 因式分解） |
| 云侧凭据共享 | 提取的证书同时出现在多个固件版本 | 跨版本比对；用 `BinDiff`/`diaphora` |
| App 侧硬编码 | APK 里的 API key、证书固定实现 | `apktool`/`jadx` + `frida` 绕过固定 |

**优先级经验**：WAN 可达 + 默认开启的风险最高（如 TOTOLINK 类 `/cgi-bin` 后门口令）。公钥弱点若「私钥可获取」则直接 = 可冒充/可登录，不是「弱加密套件」这类低危问题。

---

## 2. 命令注入与代码执行

**形成原因**：用户输入被拼接进 shell 命令；CGI 直连 shell；启动脚本变量未加引号。

**静态特征**
- C/C++：`system`、`popen`、`execl*`、`execve`、`posix_spawn` 的实参由 `sprintf`/`snprintf`/`strcat` 拼出
- 常见高危业务点：`ping`、`traceroute`、`nslookup`、`wget`/`curl`（URL 可控 → SSRF/`-o` 写文件）、`iptables`、`nvram set`、`reboot`、`dd`、`tar`、`openssl`、`insmod`
- Shell：`$(...)`、反引号、`eval`、未加引号的 `$VAR`（含 `;` `|` `&` `\n` `$( )` 注入）、`source`/`.` 加载可写路径
- CGI/PHP：`system/exec/passthru/shell_exec/proc_open/popen`、`assert($_GET)`、`preg_replace /e`
- 前端 JS：`eval`、`document.write(untrusted)`、`innerHTML` 拼接、`postMessage` 无 origin 校验

**确认方法**
1. 定位 sink（Layer 1 命中或 Track A）
2. 向上追参数来源，确认是否经过 `recv`→`sscanf`/`strtok`/JSON 解析（即可控）
3. 检查过滤：是否只过滤了 `;` 而漏 `|`/`$()`/换行；白名单是否可被绕过（`ping -c1 1.1.1.1;id`、`ping 1.1.1.1$(id)`、`%0a`）
4. Layer 4 用 Qiling hook `system` 看实参真值，或 FAT `taint`

**优先级**：未认证 + 可出网 = P0；需认证 = P1。

---

## 3. 内存破坏

| 子类 | 特征 | 确认 |
|---|---|---|
| 栈溢出 | `strcpy/strcat/sprintf/gets/scanf %s/getcwd 短缓冲/sscanf %s` 写入栈缓冲；`alloca` 大小可控 | 静态看长度校验缺失；AFL++ 模糊；Qiling hook 触发点看栈 |
| 堆溢出 | `memcpy` 长度来自报文头；`malloc(可控)` 后越界写 | 同上 |
| 整数溢出 / 符号问题 | `int` 长度字段乘法、负数长度绕过 `if(len<MAX)`、类型截断 | 手审长度校验；构造 `0xFFFFFFFF` 边界 |
| 格式化字符串 | `printf(user)`、`syslog(LOG_ERR, user)`、`fprintf(f, user)` 缺 `%s` | 检查 format 参数是否来自可控 | 
| 越界读 | `memcmp(user, fixed, n)` 提前返回 → 时序侧信道；长度未校验的 `read` | 侧信道需统计，长度需代码审查 |
| UAF / 双重释放 | 全局 `free` 后指针未置空；错误路径重复释放 | 反编译 + 模糊 |
| 解析器缺陷 | UPnP SOAP XML、JSON、TLV、ASN.1、图片（LogoFAIL 类）、字体、证书解析 | 定向模糊（该字段作为输入种子） |

**确认方法**：AFL++ 三模式之一 + 崩溃 triage（`gdb-multiarch`/`qltool` 看 PC、看是否可控）。区分「可控崩溃（潜在 RCE）」与「不可控崩溃（DoS）」。

**优先级**：可控 + 无需认证 = P0；不可控 DoS = P3。

---

## 4. Web / CGI 面

| 子类 | 特征 |
|---|---|
| 认证绕过 | 静态资源路径 `/images/../goform/xxx`、大小写变体、`.js` 后缀绕过鉴权中间件、`Referer`/`X-Forwarded-For` 做信任判断；管理端点只在前端隐藏 |
| 越权 / IDOR | 参数里的设备 ID/MAC 未与当前会话绑定 |
| CSRF | 有会话 Cookie 无 token；`SameSite` 未设；管理接口用 GET |
| 目录穿越 / 任意文件读 | `open(user_path)`、`fopen(path)` 无规范化；`../`、`%2e%2e%2f`、绝对路径、`/proc/self/environ` |
| 任意文件写 / 上传 | 上传路径可控、无扩展名与内容校验 → 写 `cgi-bin` 或 `init.d` → RCE |
| 路径注入 / Zip Slip | 解包 tar/zip 时成员名含 `../` |
| 命令类 CGI | `ping.cgi`、`traceroute.cgi`、`diag.cgi`（最经典） |
| 信息泄露页面 | `/debug`、`/status`、`/cgi-bin/dumpcfg`、备份文件 `.bak`/`.old`、源码残留 |
| 会话缺陷 | 固定 session id、可预测、无过期、token 放 URL |

**确认方法**：解包后 grep 路由字符串 → 逐个用 curl 打（隔离网络）→ 判断鉴权分支。**Track B 最关键**：对每个路由问「这个函数里有没有鉴权调用」。

---

## 5. 网络协议栈

| 协议 | 常见缺陷 |
|---|---|
| UPnP / SSDP | 无认证的 `AddPortMapping`（开 WAN 端口）、`GetExternalIPAddress`、SSDP 放大、注入 |
| HNAP | 认证逻辑缺陷（大量历史 CVE）、SOAP 注入 |
| mDNS / DNS-SD | 信息泄露、缓存投毒 |
| DNS | 中继/放大（开放解析器）、DNS rebinding 攻击内网 |
| DHCP | 伪造服务器 |
| MQTT | broker 无认证、topic 通配 `#` 越权订阅他人设备、明文、CVE-2023-3028 类认证不足 |
| CoAP | 无 DTLS、OSCORE 未启用、`/.well-known/core` 资源枚举 |
| TR-069 / CWMP | ACS 认证弱、证书不校验、URL 可篡改 |
| Telnet/SSH | 默认口令、版本老旧（dropbear 老版本）、无速率限制 |
| 私有协议 | TLV/长度字段溢出、magic 后直接 `memcpy` |
| 蓝牙 / BLE | 无配对加密、重放、可写 GATT 特征、HID 注入（BlueDucky 类） |
| Zigbee / Z-Wave | 默认网络密钥、无加密、可下发 OTA |
| RF (433/315MHz) | 固定码重放（车库门、门铃） |
| CAN（汽车） | 无认证报文、可注入（`cansend`/`candump`） |

**确认方法**：模拟环境内 `nmap -sV -sU` + 协议客户端（`mosquitto_sub`、`libcoap`、`miranda`、`Scapy`）。**Shodan/Censys 只能用来做暴露面统计，不能用来对他人设备发请求。**

---

## 6. 固件升级与信任链

| 子类 | 特征 | 确认 |
|---|---|---|
| 无签名校验 | 升级流程只有 CRC/MD5 校验、或校验值随固件一起下发可同时被改 | 读升级代码：`upgrade`、`check_firmware`、`verify`；改包重签（CRC 可重算）后打回设备 |
| 签名绕过 | 校验失败继续执行、只校验部分分区、`strcmp` 时序、签名文件可替换 | 代码审查 + 实验 |
| 降级攻击 | 无版本回滚保护（anti-rollback 未实现或 eFuse 未烧） | 刷入旧版并检查是否接受 |
| 解包路径穿越 | 升级包内文件名含 `../` 写到 `/etc/init.d` | 构造恶意包 |
| 镜像加密密钥硬编码 | 解密密钥与算法都在固件里（常见「厂商自研加密」） | `binwalk -E` 定位密文段 → 找解密函数 → 提密钥 |
| U-Boot env / bootargs 可写 | env 分区可写 → 改 `bootargs` 加 `init=/bin/sh`、`single` | 读 env 分区；UART 打断进 U-Boot |
| Secure Boot 配置错误 | FIT 签名校验未开、AVB 未强制、公钥可替换、eFuse 未锁 | `mithril --boot` 看姿态 |
| UEFI 侧 | PKfail（平台密钥未替换）、LogoFAIL（图片解析）、PixieFail（IPv6 栈） | `UEFITool` + `fwhunt-scan` + `mithril --boot bios.bin` |
| 恢复模式滥用 | TFTP/HTTP 恢复页无认证 → 直接刷任意固件 | 触摸复位按键组合进恢复模式 |

**优先级**：无需认证的升级接口 = P0（等于任意固件写入 = 持久化接管）。签名校验缺失但需认证 = P1。

---

## 7. 启动与持久化

- `init.d` 脚本以 root 运行外部可写路径的程序
- 可写分区上存放可执行文件或库（`/tmp`、`/var`、`/mnt`）→ 路径劫持
- **world-writable 二进制或脚本**：任何能以更低权限写文件的进程都能提权
- SUID/SGID 二进制：检查是否有已知漏洞或可被参数注入
- cron / `at` / `hotplug` / `udev` 规则触发可写路径
- watchdog 恢复机制：杀掉进程自动重启（模糊时要注意）
- 固件内嵌的「救援/调试」后门（通过魔数包、特制 URL 直接起 shell）

**确认**：`fw_triage.py` 输出的权限面 + 手工读 `init.d` 与 `hotplug` 脚本。

---

## 8. 调试接口与信息泄露

- UART/USB 掉出 root shell（无口令）
- `telnetd -l /bin/sh`（无需认证即 shell）
- `/proc` 挂载可读 → 内核地址、cmdline 泄露 ASLR
- core dump 落地可读 → 内存凭据
- 日志把口令/token 写进 `/var/log`
- 崩溃页面/调试页面暴露路径、版本、token
- 固件内残留源码、`.git`、编译路径、内部 IP、测试账号
- 硬件侧：JTAG/SWD 未熔断、SPI flash 未加密、eFuse 未锁

**确认**：`mithril --secrets` + 手工 `strings` 搜 `password|token|secret|debug|test|127.0.0.1|192.168|10.0.0.`。

---

## 9. 密码学实现

| 子类 | 特征 |
|---|---|
| 弱随机 | `rand()`/`srand(time(NULL))`/`random()` 用于生成 token、会话、密钥 |
| 固定 IV / salt / nonce | 硬编码 `0x00…`、常量字符串 |
| 硬编码密钥 | `AES_KEY = "1234567890abcdef"`、XOR 单字节「加密」 |
| 自研/荒谬加密 | 自建算法、ECB 模式、XOR 循环、Base64 当加密 |
| TLS 不校验证书 | `SSL_VERIFY_NONE`、`CURLOPT_SSL_VERIFYPEER 0`、自签接受任意 |
| 明文传输 | HTTP 传口令、MQTT 无 TLS、CoAP 无 DTLS |
| 摘要不当 | 用 MD5/SHA1 做完整性、自己拼 `md5(pwd+salt)` 无迭代 |
| 时序侧信道 | `strcmp` 比口令/签名、`memcmp` 提前返回 |
| Padding oracle / 重放 | 无 nonce、无时间戳校验 |

**确认**：`fat crypto-census` 普查用法；`mithril --keys` 查密钥强度；手工审关键路径（登录、会话、OTA）。

---

## 10. 运行时加固缺失

`fw_triage.py` 会给出每个二进制的加固画像。判读规则：

| 缺失项 | 影响 | 判读 |
|---|---|---|
| 无 NX（栈可执行） | 栈溢出可直接跳栈上 shellcode | 高危，显著降低利用门槛 |
| 无 PIE / 非 ET_DYN | 代码地址固定，ROP gadget 位置固定 | 高危（无 KASLR 时） |
| 无 Stack Canary | 栈溢出无检测 | 中高危 |
| 无 RELRO（Partial/None） | GOT 可写 → GOT 覆写 | 中高危 |
| 无 FORTIFY | `_chk` 系列未启用 | 中危 |
| glibc / busybox / dropbear 版本老 | 已知公开 exploit | 用 `mithril --cve` 关联，但**必须验证功能是否编译进去** |

「加固缺失」本身不是漏洞，但它是**同类漏洞优先级加权项**：一个无 NX + 无 PIE 的栈溢出，比一个全加固环境里的栈溢出严重得多。

---

## 11. 云与移动端

- AWS IoT / Azure IoT：全局共享的 X.509 私钥与证书（提取出来即全网可冒充）、策略过宽
- Firebase：数据库规则开放（`/.json` 可读）、storage 桶公开
- S3 桶：命名可猜 + 公开列表
- MQTT over WebSocket 无认证
- 移动 App：硬编码 API key、证书固定可被 Frida 绕过、`android:exported` 组件暴露、WebView `addJavascriptInterface`、本地存储明文 token、可被 ADB 备份
- 云 API 越权：用设备 token 调用户级 API、水平越权

**注意**：**不要用提取到的真实凭据去连接生产云服务**。用格式判定 + 只读的公开信息（如 Firebase 规则）判定，其余列入报告由厂商验证。

---

## 12. RTOS 与裸机

| 目标 | 关注点 |
|---|---|
| FreeRTOS / FreeRTOS-Plus-TCP | TCP/IP 栈历史漏洞（13 个 CVE 批次）、无内存保护、任务栈溢出 |
| Zephyr / MCUboot | 已披露 26 处缺陷、MCUboot 签名与回滚保护配置 |
| 裸机 MCU | 无 MMU、向量表可改写、flash 写保护未开、读保护（RDP）未开 |
| 基带 | FirmWire 类仿真、NAS/RRC 消息解析 |
| 通信栈 | BLE 协议栈（SweynTooth/BrakTooth 系列）、Wi-Fi 驱动（Broadcom/Qualcomm 栈越界） |

**确认**：`fat inspect mcu`（向量表/内存映射/外设/中断）、Renode 仿真、ChipWhisperer 做故障注入绕过读保护。

---

## 13. 每类漏洞的「确认方法」通用三步

1. **静态定位**：字符串/符号 → 引用点 → 反汇编/反编译
2. **可控性判定**：参数来源是否外部可控、是否经过过滤、是否需认证
3. **动态复现**：模拟环境触发 → 观察行为（是否崩溃、是否执行了命令、是否读到了文件）

三步缺一步，置信度就不能写 `confirmed`。
