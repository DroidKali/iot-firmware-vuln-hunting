# 沙箱执行记录

> schema `sandbox-run/1.1`　·　工具 `sandbox_run.py 1.1`

| 项 | 值 |
|---|---|
| 模式 | `sandbox`（host_fallback=False） |
| 运行时 | `docker 29.9.2`（/usr/bin/docker） |
| 镜像 | `iot-fw/qemu:latest` |
| 退出码 | 未执行 |
| 耗时 | 31.543 s |
| 是否超时 | 是 |
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
| 超时 | 30 s |
| 宿主机执行 | `forbidden` |

## 资源准入

| 项 | 值 |
|---|---|
| 决策 | `admitted`（code=—） |
| 策略 | `3b7ec7f137c8…`（来源 defaults） |
| 槽位 | 0 / 1（等待 0.0s） |
| 预算 | 1800.0 s（已用 0.038 s，剩余 1799.962 s） |
| 说明 | — |

## 挂载与指纹

| 挂载点 | 宿主机路径 | 只读 | sha256 |
|---|---|---|---|
| `/firmware` | `/root/iot-m4/fw` | 是 | `cb085f86fa415fc5aefc393a0019de7142e4e9350c76b77ce00646c71324726e` |
| `/out` | `/root/iot-m4/run-malta` | 否 | — |

## 命令

```bash
/usr/bin/docker run --rm --name iotfw-sandbox-cd69a3ec680a --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 65534:65534 --memory 512m --cpus 1 --pids-limit 128 --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /var/tmp:rw,noexec,nosuid,size=64m -e TMPDIR=/tmp -v /root/iot-m4/fw:/firmware:ro -v /root/iot-m4/run-malta:/out:rw --workdir /out iot-fw/qemu:latest /bin/sh -c 'qemu-system-mips -M malta -cpu 24Kc -m 512m -smp 1 -kernel /firmware/openwrt-19.07.2-malta-be-vmlinux.elf -drive if=ide,file=/firmware/rootfs-malta.img,format=raw -append '"'"'root=/dev/sda rw console=ttyS0,115200 init=/bin/sh ignore_loglevel panic=5'"'"' -display none -monitor none -serial file:/out/serial.log -no-reboot -snapshot'
```

## 结果

- 退出码：`未执行`　耗时 `31.543 s`　超时：是
- stdout 0 字节，stderr 0 字节

## 备注

- 输出目录 /root/iot-m4/run-malta 原模式 0755，已补 other rwx + sticky 为 1757（容器以 uid 65534:65534 写入，bind mount 不做 UID 映射）
- 固件目录含符号链接 409 个，已跳过（不跟随、不计入清单哈希）
- 固件目录含非普通文件 1 个，已跳过（不计入清单哈希）
- 固件清单哈希覆盖 1971 个文件（按相对路径排序）
- 容器不注入任何宿主机环境变量（无凭据）；输出目录已按 uid 65534:65534 调整 other rwx + sticky，写入失败仍会如实记录 exit_code
- 超时后已删除可能残留的容器：iotfw-sandbox-cd69a3ec680a
- 命令超过 30.0s 未结束，已被 kill（退出码 124）

