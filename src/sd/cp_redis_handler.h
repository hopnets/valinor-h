#ifndef CP_REDIS_HANDLER_H
#define CP_REDIS_HANDLER_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
// #include <linux/time.h>
#include <time.h>
#include <signal.h>

#include <linux/unistd.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>


#include "log.h"

#include "hiredis/hiredis.h"
#include "hiredis/async.h"
#include "hiredis/adapters/libevent.h"

#define BATCH_SIZE  32u

struct data_entry {
	__u64   ts;
    __u32   saddr;
    __u32   daddr;
    __u32   key;
   	__u16   length;
    __u16   sport;
    __u16   dport;
    
};


struct app_context {
    __u32 tid;
    __u32 commands;
    __u32 redis_key;
    __u32 total_entries;
    __u32 nr_cpus;
	redisContext *context;
    struct data_entry *collected_entries;
};

unsigned int min(unsigned int a, unsigned int b)
{
    if (a > b)
        return b;
    return a;
}

redisContext* initialize_redis();
int flush_to_redis(redisContext *c, int count);
int issue_commands(redisContext *c, struct data_entry* data, __u32 redis_key, __u32 entries);

#endif