#include "cp_redis_handler.h"

#define TS_ARRAY "/sys/fs/bpf/tc/globals/ts_map"
#define TS_IDX "/sys/fs/bpf/tc/globals/idx_map"
#define STATS "/sys/fs/bpf/tc/globals/stat_map"
#define IFINDEX 4
#define LOG_BUFFER_SIZE 1024 * 1024
#define NRCPUS  64
#define MAP_MAX_SIZE 1 << 24
enum { NS_PER_SECOND = 1000000000 };


int running = 1;
const unsigned int stats_success = 0, stats_fail = 1;


static void usage()
{
    printf("eBPF packet timestamping userspace control plane\n");
}

static void graceful_exit(int signum){

  //Return type of the handler function should be void
  log_warn("SIGINT Caught!");
  running = 0;
}

void retrieve_and_print_stats(int stats_fd)
{
    int ret, successful, failed;
    ret = bpf_map_lookup_elem(stats_fd, &stats_success, &successful);
    if (ret)
    {
        log_error("STATS: bpf_map_lookup_elem failed, %d", ret);
        return;
    }
    ret = bpf_map_lookup_elem(stats_fd, &stats_fail, &failed);
    if (ret)
    {
        log_error("STATS: bpf_map_lookup_elem failed, %d", ret);
        return;
    }
    log_info("DATAPLANE STATS:\nSUCCESSFUL CALLS: %d, FAILED CALLS: %d", successful, failed);
}

void *thread_poll(void *args)
{
    struct data_entry values[NRCPUS];
    struct timespec start;
    u_int64_t prev_value, prev_key = 0;
    struct app_context *app = (struct app_context *) args;
    int ret;
    int array_fd = -1;
    int idx_fd = -1;
    int stats_fd = -1;
    __u32 read_index = 1;
    const unsigned int map_index = 0;
    const unsigned int map_index_value = 0;
    redisContext *context;
        
    clock_gettime(CLOCK_MONOTONIC, &start);
    prev_value = start.tv_sec * NS_PER_SECOND + start.tv_nsec;
    log_info("Thread (%u): Current timestamp is %lu", app->tid, prev_value);

    // values = (struct data_entry *) malloc(app->nr_cpus * sizeof(struct data_entry));

    array_fd = bpf_obj_get(TS_ARRAY);
    if (array_fd < 0)
    {
        log_fatal("Thread (%u): bpf_obj_get(%s): %s(%d)\n", app->tid,
                  TS_ARRAY, strerror(errno), errno);
        goto thread_out;
    }
    log_info("Thread (%u): Connected to timestamp array.", app->tid);
    idx_fd = bpf_obj_get(TS_IDX);
    if (idx_fd < 0)
    {
        log_fatal("Thread (%u): bpf_obj_get(%s): %s(%d)\n", app->tid,
                  TS_IDX, strerror(errno), errno);
        goto thread_out;
    }
    log_info("Thread (%u): Connected to index store. Initializing", app->tid);
    ret = bpf_map_update_elem(idx_fd, &map_index, &map_index_value, 0);
    if (ret)
    {
        log_error("Thread (%u): bpf_map_update_elem failed, %d", app->tid, ret);
        goto thread_out;
    }
    stats_fd = bpf_obj_get(STATS);
    if (stats_fd < 0)
    {
        log_fatal("Thread (%u): bpf_obj_get(%s): %s(%d)\n", app->tid,
                  STATS, strerror(errno), errno);
        goto thread_out;
    }
    log_info("Thread (%u): Connected to stats store.", app->tid);

    app->collected_entries = (struct data_entry*) malloc(sizeof(struct data_entry)*MAP_MAX_SIZE);
    if(app->collected_entries == NULL)
    {
        log_error("Thread (%u): Failed to allocate entry array.", app->tid);
        goto thread_out;
    }


    log_info("Thread (%u): Starting poller ...", app->tid);
    while (running)
    {

        /* bpf_tunnel_key.remote_ipv4 expects host byte orders */
        ret = bpf_map_lookup_elem(array_fd, &read_index, values);
        if (ret)
        {
            log_error("Thread (%u): bpf_map_lookup_elem failed, %d", app->tid, ret);
            break;
        }
        if (values[app->tid].key != 0)
        {
            // if(value.ts != prev_value || value.key != prev_key){    // we haven't read this value before!
                // log_info("Thread %u: retrieved value: lng=%lx, tst=%x, key=%x", app->tid, values[app->tid].ts, values[app->tid].ts, values[app->tid].key);
                memcpy(&app->collected_entries[read_index-1], &values[app->tid], sizeof(struct data_entry));
                prev_value = values[app->tid].ts;
                prev_key = values[app->tid].key;
                read_index++;
                if(read_index == MAP_MAX_SIZE)
                {
                    log_info("Thread (%u): resetting the read index", app->tid);
                    read_index = 0;
                    break;  // fixme
                }
            // }
        }
        
    }

thread_out:
    app->total_entries = read_index -1;
    log_info("Thread (%u): Closing eBPF descriptors", app->tid);
    if (array_fd != -1)
        close(array_fd);
    // free(values);
    // pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    int ret, opt, i;
    int redis_key = 0;
    int *thread_return;
    int stats_fd = -1;
    int stats_initial_value = 0;
    int total_entries = 0, total_commands = 0;

    unsigned int nr_cpus = libbpf_num_possible_cpus();
    pthread_t *thread_ids;
    pthread_attr_t *thread_attrs;
    struct app_context *app_contexts;
    redisContext *context;

    // nr_cpus = 1;

    if (argc > 2)
    {
        log_error("Too many arguments.");
        goto out;
    }
    else if (argc == 2)
    {
        redis_key = atoi(argv[1]);
    }

    thread_ids = (pthread_t *) malloc(nr_cpus * sizeof(pthread_t));
    thread_attrs = (pthread_attr_t *) malloc(nr_cpus * sizeof(pthread_attr_t));
    app_contexts = (struct app_context*) malloc(nr_cpus * sizeof(struct app_context));


    log_info("Valinor: High-resolution traffic measurement framework");
    log_info("Redis key set to %u", redis_key);
    log_info("Number of CPUs: %u", nr_cpus);
    signal(SIGINT, graceful_exit); // Register signal handler
    // bpf_object__find_program_by_name(&obj, "bpf");
    stats_fd = bpf_obj_get(STATS);
    if (stats_fd < 0)
    {
        log_fatal("Thread (Main): bpf_obj_get(%s): %s(%d)\n",
                  STATS, strerror(errno), errno);
        goto out;
    }
    log_info("Thread (Main): Connected to stats store. Initializing");
    ret = bpf_map_update_elem(stats_fd, &stats_success, &stats_initial_value, 0);
    if (ret)
    {
        log_error("Thread (Main): bpf_map_update_elem failed, %d", ret);
        goto out;
    }
    ret = bpf_map_update_elem(stats_fd, &stats_fail, &stats_initial_value, 0);
    if (ret)
    {
        log_error("Thread (Main): bpf_map_update_elem failed, %d", ret);
        goto out;
    }

    // log_info("Attempting to load the eBPF kernel ...");

    for(i=0;i<nr_cpus;i++)
    {
        app_contexts[i].tid = i;
        app_contexts[i].redis_key = redis_key;
        app_contexts[i].total_entries = 0;
        app_contexts[i].nr_cpus = nr_cpus;
        ret = pthread_attr_init(&thread_attrs[i]);
        if(ret < 0)
        {
            log_error("Failed to allocate thread attributes");
            goto out;
        }
        ret = pthread_create(&thread_ids[i], &thread_attrs[i], thread_poll, (void *) &app_contexts[i]);
        if(ret < 0)
        {
            log_error("Failed to create pthread %d", i);
            goto out;
        }

    }
    for(i=0;i<nr_cpus;i++)
    {
        pthread_join(thread_ids[i], NULL);
        total_entries+=app_contexts[i].total_entries;
        log_info("Thread %d joined with %d entries", i, app_contexts[i].total_entries);
    }

    log_info("Thread (Main): Initializing Redis.");
    context = initialize_redis();
    if(context == NULL)
    {
        log_error("Thread (Main): Failed to initialize Redis.");
        goto out;
    }
    for(i=0; i < nr_cpus; i++)
    {
        if (app_contexts[i].total_entries > 0) {
            log_info("Thread (%u) retrieved a total of %d entries", i, app_contexts[i].total_entries);
            
            ret = issue_commands(context, app_contexts[i].collected_entries, redis_key, app_contexts[i].total_entries);
            log_info("Thread (%u): transferred %u entries: %u commands ready to execute", i, app_contexts[i].total_entries, ret);
            total_commands += ret;
        }
    }
    if(total_commands > 0)
    {
        ret = flush_to_redis(context, total_commands);
        log_info("Executed %u / %u  commands. Exitting ...", ret, total_commands);
    }



out:
    log_info("All operations done. %d commands executed. %d entries stored. Exitting ...", total_commands, total_entries);
    retrieve_and_print_stats(stats_fd);
    free(thread_ids);
    free(thread_attrs);
    for(i=0; i < nr_cpus; i++)
        free(app_contexts[i].collected_entries);
    free(app_contexts);

    return 0;
}