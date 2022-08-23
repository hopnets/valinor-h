DEV=enp5s0f0

OBJS= control_plane.o log.o cp_redis_handler.o

KDIR ?= /home/erfan/vebpf/src/sd/ext/libbpf

TC = /home/erfan/vebpf/src/sd/ext/iproute2/tc/tc

CP_FLAGS = -lelf -lz -lhiredis -levent -pthread -DLOG_USE_COLOR

TOOLS:= $(KDIR)
INC = -I$(KDIR)/lib \
      -I$(KDIR)/include/uapi

CLANG_INCLUDES := $(shell clang-10 -v -E - < /dev/null 2>&1 \
	| sed -n '/^\#include <...> search starts here:$$/,/^End of search list\.$$/ s/^ \+/-idirafter /p')
bpf.o: bpf.c
	rm -rf bpf.o
	clang-10 -O2 -g -target bpf $(CLANG_INCLUDES) -c $< -o $@



control_plane.o: control_plane.c
	rm -rf control_plane control_plane.o
	gcc -c $< -o $@ $(INC) $(TOOLS)/src/libbpf.a $(CP_FLAGS)

log.o: log.c
	gcc -c $< -o $@ -DLOG_USE_COLOR

control_plane: $(OBJS)
	gcc $^ -o $@ $(INC) $(TOOLS)/src/libbpf.a $(CP_FLAGS)


debug_write_indices.o: debug_write_indices.c
	rm -rf debug_write_indices debug_write_indices.o
	gcc -c $< -o $@ $(INC) $(TOOLS)/src/libbpf.a $(CP_FLAGS)

debug_write_indices: debug_write_indices.o log.o
	gcc $^ -o $@ $(INC) $(TOOLS)/src/libbpf.a $(CP_FLAGS)


run: bpf.o
	rm -f /sys/fs/bpf/tc/globals/ts_map
	rm -f /sys/fs/bpf/tc/globals/idx_map
	$(TC) qdisc replace dev $(DEV) clsact
	$(TC) filter replace dev $(DEV) egress prio 1 handle 1 bpf da obj $< sec egress
	./control_plane $(KEY) $(DURATION)

filter: bpf.o
	rm -f /sys/fs/bpf/tc/globals/ts_map
	rm -f /sys/fs/bpf/tc/globals/idx_map
	$(TC) qdisc replace dev $(DEV) clsact
	$(TC) filter replace dev $(DEV) egress prio 1 handle 1 bpf da obj $< sec egress

stop:
	$(TC) filter del dev $(DEV) ingress
	$(TC) filter del dev $(DEV) egress

clean:	stop
	rm -rf *.o
	rm control_plane

debug_ind:
	./debug_write_indices