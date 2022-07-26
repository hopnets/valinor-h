# SPDX-License-Identifier: (GPL-2.0 OR MIT)
# Copyright (C) 2021 Isovalent

DEV=enp65s0f0np0

CLANG_INCLUDES := $(shell clang -v -E - < /dev/null 2>&1 \
	| sed -n '/^\#include <...> search starts here:$$/,/^End of search list\.$$/ s/^ \+/-idirafter /p')
bpf.o: bpf.c
	clang-10 -O2 -target bpf $(CLANG_INCLUDES) -c $< -o $@

run: bpf.o
	tc qdisc replace dev $(DEV) clsact
# tc filter replace dev $(DEV) ingress prio 1 handle 1 bpf da obj $< sec ingress
	tc filter replace dev $(DEV) egress prio 1 handle 1 bpf da obj $< sec egress

clean:
	tc filter del dev $(DEV) ingress
	tc filter del dev $(DEV) egress
