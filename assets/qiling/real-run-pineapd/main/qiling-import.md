# Qiling 定向仿真结果

- 状态：FAILED
- 目标：/root/iot-m4/fw/rootfs/usr/sbin/pineapd
- 事件：5（sink-hit 0 / observed 4）
- 沙箱：mode=sandbox，host_fallback=False

## 限制

- Qiling 只模拟用户态；不覆盖内核、驱动、硬件外设与真实网络。
- 命中 trigger_marker 只证明参数到达 sink，不等于可利用；漏洞结论仍需候选验证。
- SUCCESS 只表示 Qiling 按计划跑完，不表示发现漏洞。
- Qiling 只覆盖用户态执行；内核、驱动、硬件外设与真实网络不在范围内。
- SUCCESS 只表示执行完成；sink-hit 不是漏洞结论，仍需按类型判据验证。
- 本次执行以 memory-error 结束：UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED)

## 失败/阻断

- memory-error：UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED)

本结果不是漏洞结论；sink-hit 仍需按候选类型判据复核。
