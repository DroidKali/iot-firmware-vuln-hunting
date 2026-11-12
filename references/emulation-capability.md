# 仿真能力阶梯（Emulation Capability Ladder）

本文件定义「仿真到底证明了什么」。它不替代 `references/emulation-methodology.md` 的
操作步骤，也不把计划、适配器或日志解析当成执行结果。任何一级的声明都必须有对应的
运行记录；没有记录就是未验证，不能用「应该能跑」「服务可达」推断。

状态词只用三种：

| 状态 | 含义 |
| --- | --- |
| **Verified** | 仓库内有原始产物、哈希与可复核命令，且观察结果达到该级判据 |
| **Implemented, Not Verified** | 代码或流程已存在，但没有达到该级判据的真实运行记录 |
| **Designed Only** | 只有设计、契约或计划，没有执行证据 |

## 1. 七级定义

| 级别 | 能力 | 最低判据（全部满足才算达到） | 当前状态 |
| --- | --- | --- | --- |
| **L1** | 单个 ELF 的函数/基本块 | 目标 ELF 的架构与 hash 已记录；指定入口或函数被执行；命中一个可复核的 syscall/API Hook；原始事件与退出码保存 | **Verified**（受控目标，非漏洞结论） |
| **L2** | 单进程依赖库与环境 | 动态加载器、`DT_NEEDED`、库搜索路径与所需文件系统布局可复现；进程完成一次真实文件/系统调用；失败能区分为加载器、缺库或目标自身错误 | **Verified**（单个 BusyBox applet） |
| **L3** | BusyBox/服务进程 | 真实 init 或服务启动脚本拉起目标进程；进程在 guest 内持续运行；能观察到该进程的启动参数与至少一次服务行为；仅有 shell prompt 不算 | **Implemented, Not Verified** |
| **L4** | 网络监听与请求触发 | guest 内出现预期监听套接字；从受控客户端发出请求；服务返回可归因响应；请求到 sink 的路径有 Evidence 绑定 | **Designed Only** |
| **L5** | NVRAM/配置/设备状态 | 读取真实或等价 NVRAM/配置；服务依据配置改变行为；状态来源、注入方式与回滚方式有记录 | **Designed Only** |
| **L6** | 多进程、IPC、权限与启动脚本 | 至少两个相关进程通过 IPC/信号/共享文件交互；权限与启动顺序可复现；能区分「服务未启动」与「服务启动后拒绝」 | **Designed Only** |
| **L7** | 端到端 PoC | 从外部输入到危险 sink 的完整链路可重复；PoC、请求/载荷、前置状态、观察证据与失败边界齐全；结论可由第三方按记录重放 | **Designed Only** |

级别是**证明强度**，不是漏洞严重性。L1/L2 成功不能推出 L3/L4 成功；L3 的 shell
启动也不能推出服务已运行。一个运行记录可以同时声明多级，但必须逐级列出满足的判据。

## 2. 现有证据对应的级别

| 记录 | 后端 | 目标/范围 | 达到 | 明确未达到 |
| --- | --- | --- | --- | --- |
| `assets/qiling/real-run-static/` | Qiling 1.4.6，Docker 沙箱 | 静态 MIPS `qltest-static`，`openat("/etc/QLTEST")` trigger | L1 | 动态加载、服务、网络 |
| `assets/qiling/real-run-busybox-sink/` | Qiling 1.4.11，Docker 沙箱 | 动态 MIPS/musl `busybox cat /etc/QLTEST`，guest 退出码 0 | L2（单 applet） | L3 服务常驻、L4 网络、L5–L7 |
| `assets/qemu/real-run-malta/` | QEMU 7.2.22 Malta，Docker 沙箱 | OpenWrt 19.07.2 rootfs 启动到 BusyBox `/bin/sh` | 启动流程可复现，但**不构成 L3** | 服务进程、监听端口、请求触发、NVRAM、厂商内核 |
| EMBA `L10` 导入 | 离线日志解析 | 外部工具记录的端口响应 | 只证明「日志里有一条响应」 | 本仓库没有发起请求，也没有复现该响应 |

**边界**：`service` 类型的 Fact 只表示固件里存在该服务，不代表它运行过；
`port-response` 只表示某个执行环境观察到响应，不代表本仓库能复现；Qiling 能接管
单个二进制，不代表能接管依赖 init、NVRAM 或多进程的服务。

## 3. 每级运行记录必须包含的字段

缺少任一必填字段，该次运行不得用于声明级别。可选字段不适用时写 `not-applicable`，
不要省略。

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `run_id` / `capability_level` | 是 | 与黑板一致的 run；级别取 1–7 |
| `backend` / `backend_version` | 是 | QEMU、Qiling 或其它；版本必须可核对，不能写 `latest` |
| `architecture` / `endianness` | 是 | 目标与内核/rootfs 的架构必须一致 |
| `os` / `rootfs` | 是 | 发行版/版本与 rootfs 路径；rootfs 计算 `rootfs_sha256` |
| `target` / `target_sha256` | 是 | 被测 ELF 或服务入口；静态目标必须给 hash |
| `command` / `argv` / `env` | 是 | 实际执行的完整命令与环境变量 |
| `dependencies` | 是 | 动态库、配置文件、设备节点、NVRAM 键；没有则写 `none` |
| `patches` | 是 | 对镜像、库、配置或二进制的任何修改；没有则写 `none` |
| `network` | 是 | `none`、`loopback` 或受控桥接；端口与客户端命令 |
| `expected_observation` | 是 | 运行前写下的可判定观察，不能事后补 |
| `actual_observation` | 是 | 实际 stdout/stderr/串口/事件/退出码 |
| `status` | 是 | `SUCCESS` / `PARTIAL` / `FAILED` / `BLOCKED` / `NOT_APPLICABLE` / `TIMED_OUT` |
| `failure_category` | 失败时必填 | 见 §4；不得用「没有发现」代替失败原因 |
| `artifacts` | 是 | 原始日志、JSON、串口、截图或事件文件的路径与 sha256 |
| `reproduction` | 是 | 从干净环境到该观察的最短命令序列 |
| `limitations` | 是 | 未覆盖的架构、服务、网络、配置或权限边界 |

已有的 Qiling/QEMU 记录满足与 L1/L2 相关的字段；L3 及以上所需的
`service_start`、监听套接字、请求/响应与配置来源尚未产生记录。

## 4. 失败分类

失败必须可区分，不能折叠成「仿真不可用」或「没有漏洞」：

| 类别 | 典型原因 | 建议状态 |
| --- | --- | --- |
| `sandbox-unavailable` | 没有 Docker/Podman，或策略拒绝 | `BLOCKED` |
| `unsupported-arch` | QEMU/Qiling 不支持该架构或端序 | `BLOCKED` / `NOT_APPLICABLE` |
| `kernel-format` | 内核不是可引导 ELF/镜像格式 | `FAILED` |
| `image-missing` | 镜像、rootfs 或依赖文件缺失 | `FAILED` |
| `loader-error` | 动态加载器/重定位失败 | `FAILED` |
| `missing-dependency` | 缺库、配置、设备节点或 NVRAM 键 | `FAILED` / `BLOCKED` |
| `service-not-started` | init/脚本未拉起服务 | `FAILED` |
| `network-unavailable` | 无监听、无路由或客户端不可达 | `FAILED` |
| `trigger-not-observed` | 请求已发出但未到 sink | `PARTIAL` / `FAILED` |
| `timeout` | 超过预算被 kill | `TIMED_OUT` |
| `policy-denied` | 资源准入或隔离策略拒绝 | `BLOCKED` |

`FAILED` 只说明这次执行没完成，不说明目标不存在漏洞；`NOT_APPLICABLE` 必须给出
目标与判据不适用的理由。

## 5. 晋级与声明规则

1. 只能逐级声明；声明 L4 必须已有可复核的 L3 记录。
2. 一次运行跨级时，逐级列出判据与证据，不用一个 `SUCCESS` 概括。
3. shell prompt、`init` 启动、进程存在、端口开放分别是不同观察，不能互相替代。
4. 服务级至少需要：进程在 guest 内运行 + 预期监听 + 受控请求 + 可归因响应。
5. 任何补丁、替换库或跳过 init 都必须写入记录；未记录的修改不得进入证据链。
6. 真实厂商固件、厂商内核、NVRAM 与多进程服务未验证前，文档只能写当前达到的级别。
7. 未达到的级别写 `Implemented, Not Verified` 或 `Designed Only`，不得写「部分支持」来模糊边界。

## 6. 当前未闭环项

- 真实 httpd/UPnP 服务启动与请求触发（L4）没有仓库内记录。
- NVRAM/配置注入（L5）、多进程/IPC/权限（L6）、端到端 PoC（L7）没有实现。
- QEMU 只验证 OpenWrt Malta 通用内核；厂商 ath79 内核未通过格式检查。
- Qiling 只验证静态 MIPS 目标与单个动态 BusyBox applet，未验证服务常驻。
- 上述缺口不能由 EMBA 日志、`service` Fact 或端口扫描结果补足。
