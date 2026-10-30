# 整机仿真结果（EMU-01c2df7e12c6）

❌ **FAILED**

| 项 | 值 |
|---|---|
| run / intent | RUN-PINEAPPLE-VENDOR / INTENT-M4-REAL-001 |
| backend | qemu-system unverified |
| plan | PLAN-74505b8f737d |
| image | iot-fw/qemu:latest |
| QEMU | qemu-system-mips |
| 退出 / 超时 | 1 / False |

## 失败分类

- **kernel-format**：QEMU 拒绝加载内核镜像（格式不是 ELF 或与 machine 不匹配）：qemu-system-mips: could not load kernel '/firmware/vmlinux-ath79.bin': The image is not ELF
；sandbox rc=1 stderr=[sandbox] 模式：sandbox；运行时：docker 29.9.2；网络：none
[sandbox] 固件：/root/iot-m4/fw → /firmware（只读），清单哈希：cb085f86fa415fc5aefc393a0019de7142e4e9350c76b77ce00646c71324726e
[sandbox] 输出：/root/iot-m4/run-vendor →（可重试：False）

## 限制

- 需要匹配 machine/架构的内核；不能据此判断 rootfs 不可用

## 产物

- /root/iot-m4/run-vendor/serial.log（0 字节，sha256 e3b0c44298fc）
- /root/iot-m4/run-vendor/sandbox-run.json（4301 字节，sha256 9c253018e42b）
- /root/iot-m4/run-vendor/sandbox-run.md（2845 字节，sha256 57d8d976a5a2）
- /root/iot-m4/plan-vendor.json（3999 字节，sha256 8fac88dffabf）

---

启动到 shell/login 只证明用户态可运行，不是漏洞结论；端口开放也不是漏洞。需要 Candidate 级验证时另走动态触发与证据链。
