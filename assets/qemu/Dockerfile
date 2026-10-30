# QEMU 整机仿真运行镜像（M4）
#
# 构建：
#   docker build -t iot-fw/qemu:latest assets/qemu
# 或指定包：
#   docker build --build-arg QEMU_PKGS="qemu-system-mips qemu-system-misc qemu-system-arm qemu-system-x86" \
#       -t iot-fw/qemu:latest assets/qemu
#
# 这个镜像只提供 QEMU 与 ext2 工具，不包含 EMBA、固件或任何目标 rootfs。
# 固件通过 sandbox_run.py 以只读方式挂到 /firmware，输出写到 /out。
FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG QEMU_PKGS="qemu-system-mips qemu-system-misc qemu-system-arm qemu-system-x86"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        $QEMU_PKGS e2fsprogs ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && qemu-system-mips --version

# 与 sandbox_run.py 的 --user 65534:65534 对齐；/out 由运行时挂载并授权。
USER 65534:65534
WORKDIR /out

# 不设 ENTRYPOINT：sandbox_run.py 会显式追加 `/bin/sh -c <cmd>`。
# 若这里再设 `ENTRYPOINT ["/bin/sh","-c"]`，容器会变成
# `/bin/sh -c /bin/sh -c <cmd>`，QEMU 根本不会执行。
