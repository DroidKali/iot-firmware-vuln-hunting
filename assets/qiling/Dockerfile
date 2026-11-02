# Qiling 定向仿真运行时镜像（M4）
#
# 该镜像只提供 Python + Qiling 运行时，不包含任何固件、rootfs 或目标二进制；
# 固件由 sandbox_run.py 以只读方式挂载到 /firmware，输出目录可写挂载到 /out。
# 容器以 uid/gid 65534 运行，与 sandbox_run.py 的 --user 65534:65534 一致。
#
# 构建：
#   docker build -t iot-fw/qiling:1.4.6 assets/qiling
# 验证：
#   docker run --rm iot-fw/qiling:1.4.6 python -c "import qiling; print(qiling.__version__)"

FROM python:3.11-slim

ARG QILING_VERSION=1.4.6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "qiling==${QILING_VERSION}" \
 && python -c "import qiling; print('qiling', qiling.__version__)"

USER 65534:65534
WORKDIR /out
