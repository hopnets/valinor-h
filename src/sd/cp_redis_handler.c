#include <stdio.h>
#include <string.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include "cp_redis_handler.h"


redisContext *initialize_redis()
{
    log_info("Connecting to Redis");
    redisContext *rc;

    rc = redisConnect("127.0.0.1", 6379);
    if (rc->err) {
        log_error("Redis error: %s", rc->errstr);
        return NULL;
    }
	log_info("Connected to Redis %d", rc->fd);
    return rc;
}

int flush_to_redis(redisContext *c, int count)
{
    int i, successful = 0;
    redisReply *reply;
    for(i=0;i<count;i++) {
        if(redisGetReply(c,(void *)&reply) == REDIS_OK){
            freeReplyObject(reply);
            successful++;
        }
        else {
            log_error("App redis callaback error: %s", reply->str);
        }
    }

    return successful;
}

int issue_commands(redisContext *c, struct data_entry* data, __u32 redis_key, __u32 entries)
{
    int count, ret, i, pos = 0, read_ptr = 0;
    int commands = 0;
    redisReply *reply;
    char cmd[9000];

    if(c == NULL) {
        log_error("Redis context is NULL!");
        return 0;
    }
    while (entries > 0)
    {
        pos = 0;
        count = min(BATCH_SIZE, entries);
        if (count <= 0)
            break;

        pos += sprintf(cmd, "ZADD %d", redis_key);
        for (i=0;i < count;i++)
        {
            pos += sprintf(&cmd[pos], " %llu %016" PRIx64 "%08" PRIx32 "%08" PRIx32 "%04" PRIx16 "%08" PRIx32 "%08" PRIx32 "%08" 
                    PRIx32 "%04" PRIx16 "%04" PRIx16, data[read_ptr].ts, data[read_ptr].ts, 
                    0, 0, data[read_ptr].length, data[read_ptr].key, data[read_ptr].saddr,
                    data[read_ptr].daddr, data[read_ptr].sport, data[read_ptr].dport);
            read_ptr++;
        }
        redisAppendCommand(c, cmd);
        commands++;
        entries -= count;
    }
    
    return commands;
}