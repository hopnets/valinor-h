#include "cp_redis_handler.h"

#define TS_ARRAY "/sys/fs/bpf/tc/globals/ts_map"
#define TS_IDX "/sys/fs/bpf/tc/globals/idx_map"
#define STATS "/sys/fs/bpf/tc/globals/stat_map"
#define IFINDEX 4
#define LOG_BUFFER_SIZE 1024 * 1024
#define NRCPUS  64
#define MAP_MAX_SIZE 1 << 24
#define THREAD_WARMUP_TIME 3
enum { NS_PER_SECOND = 1000000000 };


int running = 1;

static void usage()
{
    printf("eBPF packet timestamping userspace control plane debugger\n");
}

static void graceful_exit(int signum){

  //Return type of the handler function should be void
  log_warn("SIGINT Caught!");
  running = 0;
}

int main(int argc, char **argv)
{
    int ret, i;
    int index_key = 0;
    int idx_fd = -1;
    __u32 values[NRCPUS];
    unsigned int nr_cpus = libbpf_num_possible_cpus();

    log_info("Valinor: High-resolution traffic measurement framework");
    log_info("DEBUGGING: WRITE POINTERS");
    log_info("Number of CPUs: %u", nr_cpus);
    signal(SIGINT, graceful_exit); // Register signal handler

    idx_fd = bpf_obj_get(TS_IDX);
    if (idx_fd < 0)
    {
        log_error("bpf_obj_get(%s): %s(%d)\n",
                  TS_IDX, strerror(errno), errno);
        goto out;
    }

    ret = bpf_map_lookup_elem(idx_fd, &index_key, values);
        if (ret)
        {
            log_error("bpf_map_lookup_elem failed");
            goto out;
        }

    for(i=0;i<nr_cpus;i++)
    {
        log_info("CPU %d index = %u", i, values[i]);
    }


out:
    log_info("Debugger exitting.");
    return 0;
}