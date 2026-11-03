# Official linux/amd64 manifest resolved from Docker Hub on 2026-11-04 (UTC+09:00).
FROM --platform=linux/amd64 python:3.12.14-slim-bookworm@sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1

WORKDIR /app
COPY requirements.lock.txt ./requirements.lock.txt
RUN python -m pip install --only-binary=:all: --require-hashes -r requirements.lock.txt
COPY . .
RUN python -m pip install --no-deps --no-build-isolation .
CMD ["python", "-m", "quanta", "check-contracts"]
