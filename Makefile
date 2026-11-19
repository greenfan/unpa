CC ?= cc
CLANG ?= clang
PKG_CONFIG ?= pkg-config
BUILD := build
MULTIARCH := $(shell $(CC) -print-multiarch)
BPF_ENDIAN := $(shell $(CC) -dM -E - </dev/null | grep -q '^#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__' && echo bpfeb || echo bpfel)
CFLAGS ?= -O2 -g
VERSION := $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml)

.PHONY: all check check-live clean
all: $(BUILD)/unpa $(BUILD)/unpa.bpf.o

$(BUILD):
	mkdir -p $@

$(BUILD)/unpa.bpf.o: ebpf/unpa.bpf.c ebpf/unpa.h | $(BUILD)
	$(CLANG) -target $(BPF_ENDIAN) -O2 -g -Wall -Wextra -Werror $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH)) $(shell $(PKG_CONFIG) --cflags libbpf) -c $< -o $@

$(BUILD)/unpa: ebpf/main.c ebpf/nsmgr.c ebpf/report.c ebpf/nsmgr.h ebpf/report.h ebpf/classic.inc ebpf/unpa.h pyproject.toml | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra -Werror $(shell $(PKG_CONFIG) --cflags libbpf) -DUNPA_VERSION='"$(VERSION)"' ebpf/main.c ebpf/nsmgr.c ebpf/report.c $(LDFLAGS) $(shell $(PKG_CONFIG) --libs libbpf) $(LDLIBS) -lm -o $@

check: all
	$(BUILD)/unpa --version | grep -Fx 'unpa $(VERSION)'
	$(BUILD)/unpa --help >/dev/null
	! $(BUILD)/unpa --once
	! $(BUILD)/unpa -i lo -t nan
	! $(BUILD)/unpa -i lo -ii 10.0.0.0/33

check-live: all
	sh ebpf/smoke.sh

clean:
	$(RM) $(BUILD)/unpa $(BUILD)/unpa.bpf.o
	rmdir $(BUILD) 2>/dev/null || true
