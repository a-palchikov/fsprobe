MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRENTDIR := $(realpath $(patsubst %/,%,$(dir $(MKFILE_PATH))))

OUTPUTDIR := _build
BUILDDIR ?= $(CURRENTDIR)/$(OUTPUTDIR)
BPF_BUILDDIR := pkg/assets/ebpf/bytecode
GO ?= go
DOCKER ?= docker
CLANG_VER ?= 13
KERNEL_ARCH := amd64
KERNEL_VER ?= 4.19.0-18-$(KERNEL_ARCH)
CLANG ?= $(shell command -v clang 2>/dev/null || echo clang-$(CLANG_VER))
CLANG_FORMAT ?= $(shell command -v clang-format 2>/dev/null || echo clang-format-$(CLANG_VER))
LLVM_STRIP ?= $(shell command -v llvm-strip 2>/dev/null || echo llvm-strip-$(CLANG_VER))
DOCKER_BUILD_ARGS := \
	--build-arg=CLANG_VER=$(CLANG_VER) \
	--build-arg=KERNEL_VER=$(KERNEL_VER)
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
	@hack/build --target=releaser \
		$(DOCKER_BUILD_ARGS)

.PHONY: build
build: $(BPF_BUILDDIR)/probe.o | $(BUILDDIR)
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
	$(GO) build -o $(BUILDDIR) ./cmd/...

.PHONY: shell
shell: 
	@TARGET=shell OUTPUT_FORMAT="type=docker,name=build-shell:v1" \
	       hack/build \
		$(DOCKER_BUILD_ARGS)
	@$(DOCKER) run --rm -ti build-shell:v1 bash

# Build BPF code
$(BPF_BUILDDIR)/%.o: ebpf/%.c $(wildcard ebpf/*.h) | $(BPF_BUILDDIR)
	$(CLANG) -D__KERNEL__ -D__ASM_SYSREG_H \
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
