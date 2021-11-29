DEV=enp65s0f0np0

OBJS= control_plane.o log.o

KDIR ?= /lib/modules/$(shell uname -r)/source

TOOLS:= $(KDIR)/tools
INC = -I$(KDIR)/tools/testing/selftests/bpf \
      -I$(KDIR)/tools/lib \
      -I$(KDIR)/tools/include/uapi

CLANG_INCLUDES := $(shell clang-10 -v -E - < /dev/null 2>&1 \
	| sed -n '/^\#include <...> search starts here:$$/,/^End of search list\.$$/ s/^ \+/-idirafter /p')
bpf.o: bpf.c
	rm -rf bpf.o
	clang-10 -O2 -g -target bpf $(CLANG_INCLUDES) -c $< -o $@



control_plane.o: control_plane.c
	rm -rf control_plane control_plane.o
	gcc -c $< -o $@ $(INC) $(TOOLS)/lib/bpf/libbpf.a -lelf -lz

log.o: log.c
	gcc -c $< -o $@

control_plane: $(OBJS)
	gcc $^ -o $@ $(INC) $(TOOLS)/lib/bpf/libbpf.a -lelf -lz


run: bpf.o
	LD_LIBRARY_PATH=/lib/modules/5.15.2/source/tools/lib/bpf/ tc qdisc replace dev $(DEV) clsact
# tc filter replace dev $(DEV) ingress prio 1 handle 1 bpf da obj $< sec ingress
	LD_LIBRARY_PATH=/lib/modules/5.15.2/source/tools/lib/bpf/ tc filter replace dev $(DEV) egress prio 1 handle 1 bpf da obj $< sec egress

clean:
	LD_LIBRARY_PATH=/lib/modules/5.15.2/source/tools/lib/bpf/ tc filter del dev $(DEV) ingress
	LD_LIBRARY_PATH=/lib/modules/5.15.2/source/tools/lib/bpf/ tc filter del dev $(DEV) egress
	rm -rf *.o
