MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRENTDIR := $(realpath $(patsubst %/,%,$(dir $(MKFILE_PATH))))

SHELL := bash
OUTPUTDIR := _build
BUILDDIR ?= $(CURRENTDIR)/$(OUTPUTDIR)
BPF_BUILDDIR := pkg/assets/ebpf/bytecode
GO ?= go
DOCKER ?= docker
CLANG_VER ?= 13
KERNEL_ARCH := amd64
KERNEL_VER ?= 4.19.0-18-$(KERNEL_ARCH)

BUILD_LFLAGS ?=
BUILD_GO_VERSION ?= $(shell go version)

ifeq ($(BUILD_LFLAGS),)
BUILD_TIME = $(shell date -u --rfc-3339=seconds)
BUILD_BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
BUILD_COMMIT = $(shell git rev-parse HEAD | cut -c1-12)
BUILD_LFLAGS = -X 'github.com/Gui774ume/fsprobe/version.BuildTime=$(BUILD_TIME)' \
  -X 'github.com/Gui774ume/fsprobe/version.BuildGitCommit=$(BUILD_COMMIT)' \
  -X 'github.com/Gui774ume/fsprobe/version.BuildGitBranch=$(BUILD_BRANCH)'
endif

CLANG ?= $(shell command -v clang 2>/dev/null || echo clang-$(CLANG_VER))
CLANG_FORMAT ?= $(shell command -v clang-format 2>/dev/null || echo clang-format-$(CLANG_VER))
LLVM_STRIP ?= $(shell command -v llvm-strip 2>/dev/null || echo llvm-strip-$(CLANG_VER))
DOCKER_BUILD_ARGS := \
	--build-arg=CLANG_VER=$(CLANG_VER) \
	--build-arg=KERNEL_VER=$(KERNEL_VER) \
	--build-arg=BUILD_LFLAGS="$(BUILD_LFLAGS)"
INCLUDES := -I/lib/modules/$(KERNEL_VER)/build/include \
	-I/lib/modules/$(KERNEL_VER)/build/include/uapi \
	-I/lib/modules/$(KERNEL_VER)/build/include/generated/uapi \
	-I/usr/src/linux-headers-$(KERNEL_VER)/arch/x86/include/generated \
	-I/lib/modules/$(KERNEL_VER)/source/arch/x86/include \
	-I/lib/modules/$(KERNEL_VER)/source/arch/x86/include/uapi \
	-I/lib/modules/$(KERNEL_VER)/source/arch/x86/include/generated \
	-I/lib/modules/$(KERNEL_VER)/source/include
DOCKERFILE_PATH := Dockerfile
DOCKERCONTEXT_PATH = .
export DOCKERFILE_PATH DOCKERCONTEXT_PATH OUTPUTDIR

.PHONY: all
all: | $(BUILDDIR)
	@TARGET=releaser hack/build \
		$(DOCKER_BUILD_ARGS)

.PHONY: build
build: $(BPF_BUILDDIR)/probe.o | $(BUILDDIR)
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
	$(GO) build -o $(BUILDDIR) \
		-ldflags "$(BUILD_LFLAGS)" \
		./cmd/...

.PHONY: shell
shell:
	@TARGET=shell OUTPUT_FORMAT="type=docker,name=build-shell:v1" \
	       hack/build \
		$(DOCKER_BUILD_ARGS)
	@$(DOCKER) run --rm -ti build-shell:v1 bash

# Build BPF code
$(BPF_BUILDDIR)/%.o: ebpf/%.c $(wildcard ebpf/*.h) | $(BPF_BUILDDIR)
	@set -ex -o pipefail && $(CLANG) -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm \
		-D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) \
		-c $(filter %.c,$^) -o - | /usr/lib/llvm-$(CLANG_VER)/bin/llc -march=bpf -filetype=obj -o $@
	$(LLVM_STRIP) -g $@ # strip DWARF info

$(BPF_BUILDDIR):
	@mkdir -p $@

$(BUILDDIR):
	@mkdir -p $@
