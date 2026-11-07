FROM --platform=linux/arm64 ubuntu:26.04@sha256:86eb1bc1059720a19a777ba5a109e9ee3690d5dfe3e319871a6d6beb86fb7f85 AS runtime-base

COPY deploy/cp2k-armv8/install-ubuntu-packages.sh /tmp/install-ubuntu-packages.sh
RUN --mount=type=secret,id=runner_ca,target=/run/secrets/quanta-ca.pem,required=true,mode=0444 \
    bash /tmp/install-ubuntu-packages.sh runtime

FROM runtime-base AS builder
RUN --mount=type=secret,id=runner_ca,target=/run/secrets/quanta-ca.pem,required=true,mode=0444 \
    bash /tmp/install-ubuntu-packages.sh build
COPY deploy/cp2k-armv8/source-archives.sha256 /opt/quanta-build/source-archives.sha256
COPY scripts/build_cp2k_armv8.sh /usr/local/bin/build-cp2k-armv8
RUN --mount=type=secret,id=runner_ca,target=/run/secrets/quanta-ca.pem,required=true,mode=0444 \
    CURL_CA_BUNDLE=/run/secrets/quanta-ca.pem GIT_SSL_CAINFO=/run/secrets/quanta-ca.pem \
    bash /usr/local/bin/build-cp2k-armv8 fetch
ARG QUANTA_CP2K_BUILD_JOBS=3
RUN --network=none bash /usr/local/bin/build-cp2k-armv8 compile "${QUANTA_CP2K_BUILD_JOBS}"

FROM runtime-base AS runtime
COPY --from=builder /opt/quanta-cp2k /opt/quanta-cp2k
RUN --network=none printf '%s\n' /opt/quanta-cp2k/lib /opt/quanta-cp2k/deps/lib >/etc/ld.so.conf.d/quanta-cp2k.conf \
    && ldconfig \
    && rm /tmp/install-ubuntu-packages.sh \
    && ldd /opt/quanta-cp2k/bin/cp2k.psmp >/opt/quanta-cp2k/evidence/runtime-ldd.txt \
    && ! grep -F 'not found' /opt/quanta-cp2k/evidence/runtime-ldd.txt \
    && /opt/quanta-cp2k/bin/cp2k.psmp --version >/opt/quanta-cp2k/evidence/runtime-version.txt \
    && grep -F '67b5da876dd6a76b8b021d5a04d1c81ba79a4c50' /opt/quanta-cp2k/evidence/runtime-version.txt
ENV PATH="/opt/quanta-cp2k/bin:${PATH}" \
    CP2K_DATA_DIR="/opt/quanta-cp2k/share/cp2k/data" \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1
WORKDIR /work
CMD ["cp2k", "--version"]
