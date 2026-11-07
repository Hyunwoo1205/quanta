FROM --platform=linux/amd64 ubuntu:26.04@sha256:157dc3d6e4a3e4f2c68d12df9df9ed6e808b59af6d4c3757b432b4f519916725 AS runtime-base

ENV QUANTA_CP2K_ARCH=amd64
COPY deploy/cp2k-armv8/install-ubuntu-packages.sh /tmp/install-ubuntu-packages.sh
RUN --mount=type=secret,id=runner_ca,target=/run/secrets/quanta-ca.pem,required=true,mode=0444 \
    bash /tmp/install-ubuntu-packages.sh runtime

FROM runtime-base AS builder
RUN --mount=type=secret,id=runner_ca,target=/run/secrets/quanta-ca.pem,required=true,mode=0444 \
    bash /tmp/install-ubuntu-packages.sh build
COPY deploy/cp2k-armv8/source-archives.sha256 /opt/quanta-build/source-archives.sha256
COPY scripts/build_cp2k_armv8.sh /usr/local/bin/build-cp2k
RUN --mount=type=secret,id=runner_ca,target=/run/secrets/quanta-ca.pem,required=true,mode=0444 \
    CURL_CA_BUNDLE=/run/secrets/quanta-ca.pem GIT_SSL_CAINFO=/run/secrets/quanta-ca.pem \
    bash /usr/local/bin/build-cp2k fetch
ARG QUANTA_CP2K_BUILD_JOBS=3
RUN --network=none bash /usr/local/bin/build-cp2k compile "${QUANTA_CP2K_BUILD_JOBS}"

FROM runtime-base AS runtime
COPY --from=builder /opt/quanta-cp2k /opt/quanta-cp2k
RUN --network=none printf '%s\n' /opt/quanta-cp2k/lib /opt/quanta-cp2k/deps/lib >/etc/ld.so.conf.d/quanta-cp2k.conf \
    && ldconfig \
    && rm /tmp/install-ubuntu-packages.sh \
    && ldd /opt/quanta-cp2k/bin/cp2k.psmp >/opt/quanta-cp2k/evidence/runtime-ldd.txt \
    && ! grep -F 'not found' /opt/quanta-cp2k/evidence/runtime-ldd.txt \
    && /opt/quanta-cp2k/bin/cp2k.psmp --version >/opt/quanta-cp2k/evidence/runtime-version.txt \
    && grep -Fx ' Source code revision 67b5da876dd6a76b8b021d5a04d1c81ba79a4c50' /opt/quanta-cp2k/evidence/runtime-version.txt
ENV PATH="/opt/quanta-cp2k/bin:${PATH}" \
    CP2K_DATA_DIR="/opt/quanta-cp2k/share/cp2k/data" \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1
WORKDIR /work
CMD ["cp2k", "--version"]
