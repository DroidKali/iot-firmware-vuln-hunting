# 沙箱执行记录

> schema `sandbox-run/1.1`　·　工具 `sandbox_run.py 1.1`

| 项 | 值 |
|---|---|
| 模式 | `sandbox`（host_fallback=False） |
| 运行时 | `docker 29.9.2`（/usr/bin/docker） |
| 镜像 | `iot-fw/qiling:1.4.6-p212` |
| 退出码 | 1 |
| 耗时 | 6.387 s |
| 是否超时 | 否 |
| 结果 | 未成功 / 已拒绝 |

## 隔离参数

| 项 | 值 |
|---|---|
| 网络 | `none`（请求 `none`） |
| 根文件系统 | 只读 |
| 能力（cap-drop） | `--cap-drop=ALL` |
| no-new-privileges | 是 |
| 运行用户 | `65534:65534` |
| 内存 | `512m` |
| CPU | `1` |
| PID 上限 | `128` |
| tmpfs | `/tmp:rw,noexec,nosuid,size=64m` |
| 超时 | 90 s |
| 宿主机执行 | `forbidden` |

## 资源准入

| 项 | 值 |
|---|---|
| 决策 | `admitted`（code=—） |
| 策略 | `3b7ec7f137c8…`（来源 defaults） |
| 槽位 | 0 / 1（等待 0.0s） |
| 预算 | 1800.0 s（已用 0.035 s，剩余 1799.965 s） |
| 说明 | — |

## 挂载与指纹

| 挂载点 | 宿主机路径 | 只读 | sha256 |
|---|---|---|---|
| `/firmware` | `/root/iot-m4/fw` | 是 | `be146f27ed9a9ac90bb1704426e08e7304c380d35063a38d8f2e68e93b39279a` |
| `/out` | `/root/iot-m4/qiling-test/pineapd-out-1.4.6-p212` | 否 | — |

## 命令

```bash
/usr/bin/docker run --rm --name iotfw-sandbox-821c555a8748 --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 65534:65534 --memory 512m --cpus 1 --pids-limit 128 --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /var/tmp:rw,noexec,nosuid,size=64m -e TMPDIR=/tmp -v /root/iot-m4/fw:/firmware:ro -v /root/iot-m4/qiling-test/pineapd-out-1.4.6-p212:/out:rw --workdir /out iot-fw/qiling:1.4.6-p212 /bin/sh -c 'python3 /out/qiling_runner.py --plan /out/qiling-plan.json --out /out'
```

## 结果

- 退出码：`1`　耗时 `6.387 s`　超时：否
- stdout 0 字节，stderr 12317 字节

### stderr 头部

```text
WARNING: Your register accessing on id 0 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
WARNING: Your register accessing on id 0 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
WARNING: Your register accessing on id 0 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
WARNING: Your register accessing on id 57 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op
```

## 备注

- 输出目录 /root/iot-m4/qiling-test/pineapd-out-1.4.6-p212 原模式 0755，已补 other rwx + sticky 为 1757（容器以 uid 65534:65534 写入，bind mount 不做 UID 映射）
- 固件目录含符号链接 409 个，已跳过（不跟随、不计入清单哈希）
- 固件目录含非普通文件 1 个，已跳过（不计入清单哈希）
- 固件清单哈希覆盖 1973 个文件（按相对路径排序）
- 容器不注入任何宿主机环境变量（无凭据）；输出目录已按 uid 65534:65534 调整 other rwx + sticky，写入失败仍会如实记录 exit_code
- 命令已执行但返回非零（容器退出码 1）；进程退出码按约定映射为 1

