#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <linux/unistd.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>

#include "log.h"

#define TS_ARRAY "sys/fs/bpf/tc/globals/TS_ARRAY"
#define TS_IDX "sys/fs/bpf/tc/globals/TS_IDX"
#define IFINDEX 4

static void usage()
{
    printf("eBPF packet timestamping userspace control plane\n");
}

int main(int argc, char **argv)
{
    int ret, opt;
    int array_fd = -1;  // contains the timestamps, treated as circular
    int idx_fd = -1;    // [o] -> producer index, [1] -> consumer index
    const unsigned int ifindex = IFINDEX;
    const unsigned int p = 0;
    const unsigned int c = 1;

    while(opt = getopt(argc, argv, "h:") != -1)
    {
        switch(opt)
        {
            case 'h':
                usage();
                break;
            default:
                usage();
                exit(1);

        }
    }

    array_fd = bpf_obj_get(TS_ARRAY);
	if (array_fd < 0) {
        log_fatal("bpf_obj_get(%s): %s(%d)\n",
			TS_ARRAY, strerror(errno), errno);
		goto out;
	}

    idx_fd = bpf_obj_get(TS_IDX);
	if (array_fd < 0) {
        log_fatal("bpf_obj_get(%s): %s(%d)\n",
			TS_IDX, strerror(errno), errno);
		goto out;
	}

	/* bpf_tunnel_key.remote_ipv4 expects host byte orders */
	ret = bpf_map_update_elem(idx_fd, &c, &ifindex, 0);
	if (ret) {
		log_error("bpf_map_update_elem setting consumer index to 0 failed");
		goto out;
	}

out:
	if (array_fd != -1)
		close(array_fd);
	return ret;
    return 0;
}