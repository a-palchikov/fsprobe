# syntax=docker/dockerfile:1.5

ARG CLANG_VER
ARG KERNEL_VER
FROM golang:buster AS builder
ARG KERNEL_VER
ARG CLANG_VER
ENV DEBIAN_FRONTEND noninteractive
SHELL ["/bin/bash", "-xeo", "pipefail", "-c"]
RUN <<eof
    apt-get -qq update
    apt-get install --yes --no-install-recommends \
        ca-certificates \
        software-properties-common \
        bpfcc-tools \
        libelf-dev \
        zlib1g-dev \
        linux-headers-${KERNEL_VER}
    apt-get clean
    rm -rf /var/lib/apt/lists/*
eof

RUN <<eof
    wget -O - https://apt.llvm.org/llvm.sh | bash -ex /dev/stdin ${CLANG_VER}
eof

ARG BUILD_LFLAGS
FROM builder AS go-builder
WORKDIR /go/src/github.com/Gui774ume/fsprobe
COPY . .
RUN --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache <<eof
    make build \
        OUTPUT=/output \
        BUILDDIR=/_build \
        BUILD_LFLAGS="${BUILD_LFLAGS} -X 'github.com/Gui774ume/fsprobe/version.BuildGoVersion=$(go env GOVERSION)'"
eof

FROM go-builder AS shell
RUN DEBIAN_FRONTEND=noninteractive && \
    set -ex && \
    apt-get -qq install -y \
    	less
WORKDIR /go/src/github.com/Gui774ume/fsprobe
COPY . .

FROM scratch AS releaser
COPY --from=go-builder /_build/fsprobe /
