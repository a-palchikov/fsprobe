FROM golang:1.18-rc-buster AS builder

ARG CLANG_VER
ARG KERNEL_VER
#pbuilder
#aptitude
RUN DEBIAN_RELEASE=stretch DEBIAN_FRONTEND=noninteractive && \
    set -ex && \
    apt-get -qq update && \
    apt-get -y install \
        software-properties-common \
        bpfcc-tools \
        libelf-dev \
        zlib1g-dev \
        linux-headers-${KERNEL_VER}
# Install clang
RUN set -ex && \
    wget -O /tmp/llvm.sh https://apt.llvm.org/llvm.sh && \
    chmod +x /tmp/llvm.sh && \
    /tmp/llvm.sh ${CLANG_VER} && \
    rm /tmp/llvm.sh

FROM builder AS go-builder
WORKDIR /go/src/github.com/Gui774ume/fsprobe
COPY . .
RUN --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    set -ex && \
    make build \
        OUTPUT=/output \
        BUILDDIR=/_build

FROM builder AS shell
WORKDIR /go/src/github.com/Gui774ume/fsprobe
COPY . .

FROM scratch AS releaser
COPY --from=go-builder /_build/fsprobe /
