#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
// #include <linux/time.h>
#include <time.h>

#include <linux/unistd.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "log.h"

#define TS_ARRAY "/sys/fs/bpf/tc/globals/ts_map"
#define TS_IDX "/sys/fs/bpf/tc/globals/idx_map"
#define IFINDEX 4
#define LOG_BUFFER_SIZE 1024 * 1024
#define MAP_MAX_SIZE 1 << 24
enum { NS_PER_SECOND = 1000000000 };

struct data_entry {
	__u64	ts;
	__u64	length;
};


static void usage()
{
    printf("eBPF packet timestamping userspace control plane\n");
}

int main(int argc, char **argv)
{
    int ret, opt;
    int array_fd = -1;
    int idx_fd = -1;
    uint32_t read_index = 1;
    const unsigned int map_index = 0;
    const unsigned int map_index_value = 0;
    struct timespec start;
    u_int64_t old_value;
    struct data_entry value;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    old_value = start.tv_sec * NS_PER_SECOND + start.tv_nsec;

    log_info("Current timestamp is %lu", old_value);
    // char log_buffer[LOG_BUFFER_SIZE];
    // struct bpf_load_program_attr attr;

    while (opt = getopt(argc, argv, "h:") != -1)
    {
        switch (opt)
        {
        case 'h':
            usage();
            break;
        default:
            usage();
            exit(1);
        }
    }
    log_info("Valinor: High-resolution traffic measurement framework");


    // bpf_object__find_program_by_name(&obj, "bpf");

    // log_info("Attempting to load the eBPF kernel ...");

    array_fd = bpf_obj_get(TS_ARRAY);
    if (array_fd < 0)
    {
        log_fatal("bpf_obj_get(%s): %s(%d)\n",
                  TS_ARRAY, strerror(errno), errno);
        goto out;
    }
    log_info("Connected to timestamp array.");
    idx_fd = bpf_obj_get(TS_IDX);
    if (idx_fd < 0)
    {
        log_fatal("bpf_obj_get(%s): %s(%d)\n",
                  TS_IDX, strerror(errno), errno);
        goto out;
    }
    log_info("Connected to index store. Initializing");
    ret = bpf_map_update_elem(idx_fd, &map_index, &map_index_value, 0);
    if (ret)
    {
        log_error("bpf_map_update_elem failed, %d", ret);
        goto out;
    }
    log_info("Starting poller ...");
    while (1)
    {

        /* bpf_tunnel_key.remote_ipv4 expects host byte orders */
        ret = bpf_map_lookup_elem(array_fd, &read_index, &value);
        if (ret)
        {
            log_error("bpf_map_lookup_elem failed, %d", ret);
            goto out;
        }
        if (value.ts > old_value)
        {
            log_info("retrieved value: %lu, %lu (%lu)", value.ts, value.length, read_index);
            old_value = value.ts;   
            read_index++;
            if(read_index == MAP_MAX_SIZE)
            {
                log_info("resetting the read index");
                read_index = 0;
            }
        }


    }

out:
    if (array_fd != -1)
        close(array_fd);
    return ret;
    return 0;
}