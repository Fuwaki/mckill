# requires: clang llvm libbpf-dev bpftool
CLANG      ?= clang
BPFTOOL    ?= bpftool
STRIP      ?= strip
LLVM_STRIP ?= llvm-strip
ARCH       := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

# BPF needs BTF; strip DWARF after compile, scrub source-path C-strings
CFLAGS_BPF := -g -O2 -Wall \
	-fdebug-prefix-map=$(CURDIR)=. \
	-ffile-prefix-map=$(CURDIR)=. \
	-fmacro-prefix-map=$(CURDIR)=.

# userspace: no local symbols, drop metadata, modest anti-analysis
CFLAGS_USR := -O2 -Wall \
	-fvisibility=hidden \
	-fno-ident \
	-fno-asynchronous-unwind-tables \
	-fno-unwind-tables \
	-fomit-frame-pointer \
	-ffunction-sections \
	-fdata-sections \
	-fno-stack-protector

LDFLAGS_USR := -s \
	-Wl,--gc-sections \
	-Wl,--build-id=none \
	-Wl,--as-needed \
	-Wl,-z,now \
	-Wl,-z,relro \
	-Wl,--hash-style=gnu \
	-Wl,--exclude-libs,ALL

LIBS := -lbpf -lelf -lz

STRIP_FLAGS := --strip-all \
	--remove-section=.comment \
	--remove-section=.note \
	--remove-section=.note.gnu.property \
	--remove-section=.note.ABI-tag \
	--remove-section=.eh_frame \
	--remove-section=.eh_frame_hdr \
	--remove-section=.sframe \
	--remove-section=.gnu.build-id

.PHONY: all clean
all: mckill

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

mckill.bpf.o: mckill.bpf.c vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) $(CFLAGS_BPF) -c $< -o $@
	# keep .BTF + .BTF.ext (func_info needed to load); drop DWARF only
	$(LLVM_STRIP) -g $@
	python3 scrub_paths.py $@

mckill.skel.h: mckill.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

mckill: mckill.c mckill.skel.h
	$(CLANG) $(CFLAGS_USR) $< -o $@ $(LDFLAGS_USR) $(LIBS)
	$(STRIP) $(STRIP_FLAGS) $@

clean:
	rm -f mckill mckill.bpf.o mckill.skel.h vmlinux.h
