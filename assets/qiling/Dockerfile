# Qiling 定向仿真运行时镜像（M4）
#
# 该镜像只提供 Python + Qiling 运行时，不包含任何固件、rootfs 或目标二进制；
# 固件由 sandbox_run.py 以只读方式挂载到 /firmware，输出目录可写挂载到 /out。
# 容器以 uid/gid 65534 运行，与 sandbox_run.py 的 --user 65534:65534 一致。
#
# 构建（Qiling 1.4.11 不在 PyPI，必须从 GitHub tag/commit 安装）：
#   docker build -t iot-fw/qiling:1.4.11 assets/qiling
# 验证：
#   docker run --rm iot-fw/qiling:1.4.11 python -c "import qiling; print(qiling.__version__)"

FROM python:3.11-slim-bookworm

ARG QILING_VERSION=1.4.11
ARG QILING_COMMIT=86c927cb329993b14e2586e04d1dd7a90deee5fb

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git gcc libc6-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      "qiling @ git+https://github.com/qilingframework/qiling@${QILING_COMMIT}" \
 && python -c "import sys, qiling; print('qiling', qiling.__version__); sys.exit(0 if qiling.__version__ == '${QILING_VERSION}' else 1)"

USER 65534:65534
WORKDIR /out
