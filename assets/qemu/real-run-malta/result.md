# 整机仿真结果（EMU-7b2e141b296c）

✅ **SUCCESS**

| 项 | 值 |
|---|---|
| run / intent | RUN-PINEAPPLE-001 / INTENT-M4-REAL-001 |
| backend | qemu-system unverified |
| plan | PLAN-e23e2aa53de7 |
| image | iot-fw/qemu:latest |
| QEMU | qemu-system-mips |
| 退出 / 超时 | 124 / True |

## 观察（仅仿真事实）

- [console-success] / # 
- [kernel-boot] Linux version

## 限制

- 达到观察窗口后由沙箱终止；已观察到 shell-prompt，不表示进程/服务稳定
- 达到观察窗口后由沙箱终止；shell/login 已出现，但未验证服务稳定性

## 产物

- /root/iot-m4/run-malta/serial.log（11675 字节，sha256 023df23e953e）
- /root/iot-m4/run-malta/sandbox-run.json（4272 字节，sha256 679fcc60232e）
- /root/iot-m4/run-malta/sandbox-run.md（2795 字节，sha256 b803d9f6be48）
- /root/iot-m4/plan-malta.json（4012 字节，sha256 7f309d958aae）

---

启动到 shell/login 只证明用户态可运行，不是漏洞结论；端口开放也不是漏洞。需要 Candidate 级验证时另走动态触发与证据链。
