# 外部资源索引（awesome-connected-things-sec 精编）

来源：`https://github.com/V33RU/awesome-connected-things-sec`（在线版 `https://v33ru.github.io/awesome-connected-things-sec/`）。
原列表有 1000+ 条目，本文件只保留**对固件漏洞挖掘流水线有直接作用**的，并按 Phase 映射。需要更全的清单时直接查原仓库。

---

## 按 Phase 映射

| Phase | 该读什么 |
|---|---|
| 0-1 提取 | Firmware Security → Extraction / Static Analysis Tools |
| 0-1 内容 | Firmware Security → Static Analysis Tools（EMBA、FACT、firmwalker、fwanalyzer、ByteSweep）、Defensive Security → Threat Modeling |
| 2 分层 | Firmware Security → Fundamentals（OWASP FWSTM、ISVS，用于定义「什么算该查的」） |
| 3 审计 | Firmware Security → Reverse Engineering Tools / Router Firmware Analysis、Network and Web Protocols |
| 4 模拟模糊 | Firmware Security → Dynamic Analysis and Emulation / OTA Update Security、Tools → Fuzzing Tools |
| 4 硬件 | Hardware Attacks 全章 |
| 5 报告 | Defensive Security → Secure Development / Guidelines and Standards、Learning Resources → Vulnerability Guides |
| 全程 | Research and Community → Blogs / Researchers to Follow |

---

## Firmware Security

### Fundamentals（方法论与标准，Phase 2 用于定义核查范围）
- OWASP Firmware Security Testing Methodology（FWSTM）— 固件测试的标准流程
- OWASP IoT Security Verification Standard（ISVS）— 可核查条目清单，报告里的「应有控制」依据
- Reversing 101
- Hands-on Firmware Extraction, Exploration, and Emulation

### Extraction（Phase 1）
- **unblob** — 提取框架，78+ 格式，chunk 精确定位
- **Binwalk v3** — 签名识别 + 熵分析（Rust 重写）
- **EMBA** — 嵌入式 Linux 固件全自动分析（含仿真与 CVE）
- **FACT** — 固件分析与比对平台（多版本 diff）
- **Firmwalker** — 关键字扫描脚本
- **fwanalyzer** — 策略化固件检查
- **ByteSweep**、**BINSEC**、**Firmware Modification Kit**
- Firmware Samples — firmware.center（练手样本）
- BasicFUN 系列（SPI Flash 提取 / 重刷）

### Static Analysis Tools（Phase 1 内容级 + Phase 3 Layer 1）
- EMBA、FACT、Binwalk v3、Firmwalker、fwanalyzer
- **fwhunt-scan** — UEFI 固件分析
- **unblob**、**Checksec.sh**（加固检查；`fw_triage.py` 复刻其核心判据）
- Firmware Modification Kit

### Dynamic Analysis and Emulation（Phase 4）
- **Firmadyne** / **FirmAE** — 自动化固件仿真（FirmAE 成功率更高）
- **QEMU**（system / user）、**PANDA**、**SymQEMU**、**S2E**
- **Avatar2** — 动态分析编排（模拟器 + 真实硬件混合）
- **Renode** — 嵌入式系统/RTOS 仿真
- **Unicorn Engine** — CPU 仿真引擎
- **Qiling Framework** — 高级二进制仿真与插桩（本 skill 主用）
- **HALucinator** — 通过 HAL 替换做固件再宿主化
- **FirmWire** — 基带固件仿真
- **Icicle** — 灰盒固件模糊专用模拟器
- Emulation Tutorials 里值得读的：*Emulating ARM Router Firmware (Azeria Labs)*、*Simulating and Hunting Firmware Vulnerabilities with Qiling*、*D-Link: Emulating Firmware and Hacking Hardware*、*My Emulation Goes to the Moon… Until False Flag*（仿真假阳性的经典案例）

### OTA Update Security（Phase 3 Track B 必查面）
- IoT Firmware Security and Update Mechanisms
- Secure OTA Boot Chains and Firmware Verification
- Top 10 IoT Vulnerabilities - OTA Update Attacks
- Review of IoT Firmware Vulnerabilities and Auditing Techniques

### RTOS Security（裸机目标必查）
- Zephyr：Zephyr Vulnerabilities List、NCC Group Zephyr/MCUboot Assessment、26 Flaws in Zephyr and MCUboot
- FreeRTOS：FreeRTOS 13 Vulnerabilities in TCP/IP Stack、Exploiting Memory Corruption in FreeRTOS

### Reverse Engineering Tools（Phase 3 Layer 3）
- Ghidra、IDA Pro、**Radare2**、Cutter、Binary Ninja、GDB
- **Diaphora**、**Ghidriff** — 二进制比对（官方补丁 diff 定位漏洞利器）
- **Angr** — 符号执行
- **Frida** — 动态插桩
- **MCP / 模型直连反编译器**（让模型拿到真语义而不是字符串猜谜）：
  - **`ida-mcp`**（`HexRaysSA/ida-mcp`，官方 Hex-Rays）— IDA **9.4+** + idalib；六工具（`open_database` / `execute_python` / `reference` / `list_databases` / `save_database` / `close_database`），能力集中在 `execute_python`（跑 ida-domain / IDAPython，直接取伪代码与 xref）。配套 `ida-nexus`（多客户端共享 IDB）、`ida-domain`（IDA 9.1+ 的 Python API，`db.functions` / `db.xrefs` / `db.pseudocode` / `db.strings` / `db.bytes` / `db.types` / `db.signature_files`）。社区插件市场 `HexRaysSA/claude-marketplace` 等。
  - **`pyghidra-mcp`** — 无头 Ghidra MCP（免费路线）
- RetDec、rev.ng、Ret-sync
- 教程：*Reversing Firmware with Radare*、*Breaking Firmware Encryption*、*Automating Binary Vulnerability Discovery with Ghidra and Semgrep*、*Finding Bugs in Netgear Router*

### ARM Exploitation / Binary Analysis
- Azeria Labs ARM Tutorials、ARM Exploitation for IoT、DVAR（Damn Vulnerable ARM Router）
- *We are ARMed no more ROPpery Here*、ARM64 Reversing and Exploitation Series
- Practical Binary Analysis

### Secure Boot / UEFI（信任链与提权）
- Pwn the ESP32 Secure Boot、ESP32 Secure Boot Bypass (CVE-2020-13629)、Amlogic S905 SoC Bypassing Secure Boot
- U-Boot USB DFU Vulnerability (CVE-2022-2347)、Breaking Secure Boot on Silicon Labs Gecko
- **PKfail**（平台密钥未替换）、**LogoFAIL**（图片解析）、**PixieFail**（EDK II IPv6 栈）、Hydroph0bia（Insyde H2O SecureBoot bypass）
- UEFI Firmware Rootkits: Myths and Reality

### Symlink Attacks
- Zip Slip（升级包解包路径穿越的标准参考）

### Router Firmware Analysis（Phase 2/3 的实战范式）
- *A Journey into IoT* 四部曲（组件与端口 → 固件 dump 与分析 → 无线通信 → 内部通信）
- Dynamic Analysis of Firmware Components in IoT Devices
- TP-Link Firmware Decryption C210 V2（含 bootloader 解密思路）

### Router Exploitation（漏洞类型与利用范式，读它学「找什么」）
- Hunting for Unauthenticated n-days in Asus Routers
- *Puckungfu 2*（NETGEAR WAN 命令注入）、*PwnAgent*（RAX 系列一键 WAN RCE）
- ROPing our way to RCE、ROPing Routers from scratch: Tenda Ac8v4
- CVE-2024-54887（TP-Link）、CVE-2025-9961（TP-Link AX10）
- Blackbox-Fuzzing of IoT Devices Using Router TL-WR902AC
- 系列：Netgear Orbi（UART → SOAP 崩溃 → N-day）、TP-Link TDDP 溢出、Cisco RV110W patch diffing

---

## Hardware Attacks（Phase 4.4，必须物理接触时）

### 接口攻击
| 接口 | 关键资料 |
|---|---|
| UART | *Identifying UART Interface*、*Reverse Engineering Serial Ports*、*Intro to Embedded RE: UART Discovery and Firmware Extraction via UBoot*、*Dumping Firmware Through UART* |
| JTAG | *Hardware Hacking 101: Introduction to JTAG*、*How to Find the JTAG Interface*、*Bus Pirate JTAG + OpenOCD*、*Extracting Firmware from External Memory via JTAG* |
| SWD | *SWD Protocol Overview (HardBreak)*、*Practical SWD Attack Surface*、LibSWD |
| SPI | *Extracting Firmware from Embedded Devices (SPI NOR)*、*Dumping eMMC Flash*、TPM 2.0 BitLocker 密钥提取 |
| I2C | *Hardware Attack Surface I2C*、*I2C Injection with Bus Pirate* |
| TPM | Introduction to TPM、TPM Security Defeated in 30 Minutes |

### 内存提取与故障注入
- eMMC：eMMC Protocol、**RPMB: A Secret Place Inside the eMMC**
- 电压毛刺：*Voltage Glitching with Crowbars*、*Glitcher Part 1: Reproducible Voltage Glitching on STM32*、*Keys in Flash - Glitching AES Keys from Arduino*
- 功耗分析：*Breaking AES with ChipWhisperer*、ChipWhisperer Wiki
- BootROM 攻击：*Dumping the Amlogic A113X Bootrom*、*There's A Hole In Your SoC: Glitching the MediaTek BootROM*
- PCIe/DMA：*PCIe DMA Attack against a Secured Jetson Nano (CVE-2022-21819)*

---

## 网络与协议

### MQTT（Phase 3 Track B + Phase 4 协议测试）
- *MQTT Broker Security 101*、*Hacking the IoT with MQTT*、*IoT Security: RCE in MQTT Protocol*
- 工具：**IoXY**（MQTT 拦截代理）、**MQTT-PWN**、Mosquitto、MQTT Explorer、Nmap MQTT 库
- 已知 CVE：CVE-2023-3028（认证不足 CVSS 9.8）、CVE-2020-13849、CVE-2019-5432、CVE-2021-0229
- 经典案例：Sesame 智能门锁渗透、Servisnet Tessa MQTT 凭据泄露、MQTT 门铃

### CoAP
- RFC 8613（OSCORE）、RFC 8323、RFC 8824
- 工具：libcoap CLI、Scapy CoAP 插件、Copper4Cr、Californium、Nmap `coap` NSE
- *CoAP Exposure Study (2024)*

### mTLS（固件与云的信任关系）
- *mTLS: When Certificate Authentication is Done Wrong*（必读）
- *Hands On IoT MitM Part 1 - AWS IoT MQTT + mTLS Interception*
- *OWASP MASTG-TECH-0012: Bypassing Certificate Pinning in Android IoT Companion Apps*
- AWS IoT X.509 客户端证书与车队配置、Azure IoT Hub mTLS X.509 CA 认证

### IoT Protocols Overview
- *Attacking IoT Devices from Web Perspective*、Awesome Industrial Protocols、IoT Architecture

---

## 云与移动端（Phase 3 Track B）

- AWS：AWS Pentesting Guide、**CloudFox**（云攻击路径）、**S3Scanner**、**Pacu**、**ScoutSuite**、**Prowler**
- Firebase：Firebase Security Rules Testing、Misconfigured Firebase Databases
- Android：Android App Reverse Engineering 101、Android Application Pentesting Book、OWASP MASTG、Intercepting HTTPS Communication in Flutter
- iOS：iOS Pentesting Guide、OWASP MSTG

---

## Tools

### 软件 / 利用框架
- **Expliot Framework**、**RouterSploit**、**HomePwn**、**PENIOT**、BlueSploit、IoTSecFuzz、ISF（工控）、HAL（硬件分析）、PRET（打印机）、Shambles
- **Firmware Analysis Toolkit (FAT)** — Attify 出品，本 skill Phase 4 首选编排工具
- Samsung Firmware Magic（厂商固件格式解析）

### 模糊测试
- *The art of Fuzzing: Introduction*、*A LibAFL Introductory Workshop*、*The Blitz Tutorial Lab on Fuzzing with AFL++*
- **AFL++**（本 skill 主用）、**boofuzz**、**Fuzzowski**、Syzkaller、Dr. Memory
- IoT 专用：FIRM-AFL（高吞吐固件模糊）、Snipuzz（黑盒固件模糊）、Frankenstein（Broadcom/Cypress 仿真模糊）、Awesome Embedded Fuzzing
- *Fuzzing IoT Binaries Part 1/2*、*Fuzzing ICS Protocols*

### 硬件工具
- Bus Pirate、Shikra、Attify Badge、**Flipper Zero**、HackRF、RTL-SDR
- 逻辑分析仪（Saleae）、**JTAGulator**、EEPROM 编程器/SOIC 夹
- 调试适配器：ST-Link、Segger J-Link、FTDI、Black Magic Probe
- USB：FaceDancer21、RfCat

### 渗透测试系统（装环境最省事）
- **AttifyOS**、IoT Pentesting OS、EmbedOS
- Dragon OS / Skywave Linux（SDR）、Sigint OS

### 搜索引擎（只用于暴露面统计，不得对他人设备发请求）
- Shodan、Censys、ZoomEye、BinaryEdge、Wigle、FCC ID Database、CVE PoC Search

---

## Defensive Security（写报告与给出修复建议时的依据）

### 威胁建模
- OWASP Threat Modeling Process、STRIDE Guide
- IoT 特定：Smart Home / Smart Solar / Healthcare / Agriculture 的 STRIDE 案例

### 加固与标准
- **Compiler Options Hardening Guide for C and C++**（用来说明「为什么无 NX/PIE 是问题」）
- Embedded Linux Hardening、IoT Device Hardening Best Practices、Linux Hardening Guide
- **NISTIR 8259**、**NIST SP 800-213**、**ETSI EN 303 645**、OWASP IoT Top 10、OWASP IoT Project

### 事件响应与取证
- IoT Forensics and Incident Response、Embedded Device Forensics

---

## Learning Resources

- 培训平台：OpenSecurityTraining2、cryptopals
- Cheatsheets：Hardware Hacking Cheatsheet、Nmap Tutorial、Pentest Hardware Handbook、THC's favourite Tips Tricks & Hacks
- Vulnerability Guides：OWASP IoT Top 10 2018 Mapping
- Labs & CTFs：Vulnerable Applications、CTF Competitions、Lab Setup（DVAR 是 ARM 路由器漏洞练习的经典靶场）
- Books / YouTube Channels：见原仓库对应章节

---

## Research and Community（跟进新漏洞与手法）

- Technical Research、Blogs、Community Platforms、Villages
- Researchers to Follow
- Device-Specific Research（按设备型号的既有研究，挖之前先查有没有人做过）
- TrustZone and TEE Research
- Pwn2Own Research（每年 IoT/Automotive 的完整利用链是最好的学习材料）
- **MCP / AI Agent** 章节（AI 辅助漏洞挖掘的最新工具）

---

## 使用建议

1. **开工前先查「有没有人挖过这台设备」**：Device-Specific Research + Shodan/Censys + CVE 检索。已有的 n-day 仍然要走完整流水线验证（厂商可能只修了一半），但可以显著缩短 Phase 3。
2. **读 2-3 篇同品类的利用链**（如 Router Exploitation 里的对应厂商），建立「这类设备通常在哪里出问题」的先验，把它写进 Phase 2 的分配提示里。
3. **学习材料不要当噪音**：Emulation Tutorials 里的 *My Emulation Goes to the Moon… Until False Flag* 和 *Challenges and Pitfalls while Emulating Icelandic Household Routers* 是避免仿真误报的必读。
