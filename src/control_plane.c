#include "cp_redis_handler.h"

#define TS_ARRAY "/sys/fs/bpf/tc/globals/ts_map"
#define TS_IDX "/sys/fs/bpf/tc/globals/idx_map"
#define STATS "/sys/fs/bpf/tc/globals/stat_map"
#define ENABLE "/sys/fs/bpf/tc/globals/enb_map"
#define IFINDEX 4
#define LOG_BUFFER_SIZE 1024 * 1024
#define NRCPUS 64
#define MAP_MAX_SIZE 1 << 24
#define THREAD_WARMUP_TIME 1
enum
{
    NS_PER_SECOND = 1000000000
};

int running = 1;
const unsigned int stats_success = 0, stats_fail = 1;

static void usage()
{
    printf("Valinor-H eBPF packet timestamping userspace control plane\n");
}

static void graceful_exit(int signum)
{
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
    log_info("=============================\nFINAL DATAPLANE STATS:\nSUCCESSFUL CALLS: %d, FAILED CALLS: %d", successful, failed);
}

void retrieve_and_print_stats_brief(int stats_fd, int *prev_calls)
{
    int ret, successful, failed, rate = 0;
    ret = bpf_map_lookup_elem(stats_fd, &stats_success, &successful);
    if (ret)
    {
        return;
    }
    ret = bpf_map_lookup_elem(stats_fd, &stats_fail, &failed);
    if (ret)
    {
        return;
    }
    log_fatal("DATAPLANE STATS: SUCCESSFUL CALLS: %d, FAILED CALLS: %d, CALL/S: %d", successful, failed, (successful + failed) - *prev_calls);
    *prev_calls = successful + failed;
}

void *thread_poll(void *args)
{
    struct data_entry values[NRCPUS];
    struct timespec start;
    __u64 start_time, current_time, prev_value, prev_key = 0;
    struct app_context *app = (struct app_context *)args;
    int ret;
    int array_fd = -1;
    int idx_fd = -1;
    int stats_fd = -1;
    int working = 1, capture = 1;
    __u32 read_index = 1;
    const unsigned int map_index = 0;
    redisContext *context;

    array_fd = bpf_obj_get(TS_ARRAY);
    if (array_fd < 0)
    {
        log_error("Thread (%u): bpf_obj_get(%s): %s(%d)\n", app->tid,
                  TS_ARRAY, strerror(errno), errno);
        goto thread_out;
    }
    log_info("Thread (%u): Connected to timestamp array.", app->tid);
    idx_fd = bpf_obj_get(TS_IDX);
    if (idx_fd < 0)
    {
        log_error("Thread (%u): bpf_obj_get(%s): %s(%d)\n", app->tid,
                  TS_IDX, strerror(errno), errno);
        goto thread_out;
    }

    stats_fd = bpf_obj_get(STATS);
    if (stats_fd < 0)
    {
        log_error("Thread (%u): bpf_obj_get(%s): %s(%d)\n", app->tid,
                  STATS, strerror(errno), errno);
        goto thread_out;
    }
    log_info("Thread (%u): Connected to stats store.", app->tid);

    app->collected_entries = (struct data_entry *)malloc(sizeof(struct data_entry) * MAP_MAX_SIZE);
    if (app->collected_entries == NULL)
    {
        log_error("Thread (%u): Failed to allocate entry array.", app->tid);
        goto thread_out;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    start_time = start.tv_sec * NS_PER_SECOND + start.tv_nsec;
    log_info("Thread (%u): Current timestamp is %lu", app->tid, prev_value);
    prev_value = start_time;

    log_info("Thread (%u): Starting poller ...", app->tid);
    while (running || working)
    {

        ret = bpf_map_lookup_elem(array_fd, &read_index, values);
        if (ret)
        {
            log_error("Thread (%u): bpf_map_lookup_elem failed, %d", app->tid, ret);
            break;
        }
        if (values[app->tid].ts != 0)
        {
            memcpy(&app->collected_entries[read_index - 1], &values[app->tid], sizeof(struct data_entry));
            prev_value = values[app->tid].ts;
            prev_key = values[app->tid].key;
            read_index++;
            if (read_index == MAP_MAX_SIZE)
            {
                log_info("Thread (%u): resetting the read index", app->tid);
                read_index = 0;
                break;
            }
            working = 1;
        }
        else
            working = 0;
    }

thread_out:
    app->total_entries = read_index - 1;
    log_info("Thread (%u): Closing eBPF descriptors", app->tid);
    if (array_fd != -1)
        close(array_fd);
}

int main(int argc, char **argv)
{
    int ret, opt, i;
    int redis_key = 0;
    int *thread_return;
    int stats_fd = -1;
    int idx_fd = -1;
    int enb_fd = -1;
    int stats_initial_value = 0;
    int total_entries = 0, total_commands = 0;
    int prev_calls = 0;
    __u64 capture_duration = 0;
    struct timespec start;
    __u64 start_time, current_time = 0;
    const unsigned int map_index = 0;
    const unsigned int map_idle_value = 0, map_capture_value = 1;

    unsigned int nr_cpus = libbpf_num_possible_cpus();
    pthread_t *thread_ids;
    pthread_attr_t *thread_attrs;
    struct app_context *app_contexts;
    redisContext *context;

    if (argc > 3)
    {
        log_error("Too many arguments.");
        goto out;
    }
    else if (argc == 3)
    {
        redis_key = atoi(argv[1]);
        capture_duration = atoi(argv[2]);
    }
    else if (argc == 2)
    {
        redis_key = atoi(argv[1]);
    }

    thread_ids = (pthread_t *)malloc(nr_cpus * sizeof(pthread_t));
    thread_attrs = (pthread_attr_t *)malloc(nr_cpus * sizeof(pthread_attr_t));
    app_contexts = (struct app_context *)malloc(nr_cpus * sizeof(struct app_context));

    log_info("Valinor: High-resolution traffic measurement framework");
    log_info("Redis key set to %u", redis_key);
    if (capture_duration)
        log_info("Capture duration set to %llus", capture_duration);
    else
        log_info("Capture duration is unlimited");
    log_info("Number of CPUs: %u", nr_cpus);
    signal(SIGINT, graceful_exit);
    stats_fd = bpf_obj_get(STATS);
    if (stats_fd < 0)
    {
        log_error("Thread (Main): bpf_obj_get(%s): %s(%d)\n",
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

    idx_fd = bpf_obj_get(TS_IDX);
    if (idx_fd < 0)
    {
        log_error("Thread (Main): bpf_obj_get(%s): %s(%d)\n",
                  TS_IDX, strerror(errno), errno);
        goto out;
    }
    log_info("Thread (Main): Connected to index store.");

    enb_fd = bpf_obj_get(ENABLE);
    if (enb_fd < 0)
    {
        log_error("Thread (Main): bpf_obj_get(%s): %s(%d)\n",
                  ENABLE, strerror(errno), errno);
        goto out;
    }
    log_info("Thread (Main): Connected to enable store. ");

    for (i = 0; i < nr_cpus; i++)
    {
        app_contexts[i].tid = i;
        app_contexts[i].redis_key = redis_key;
        app_contexts[i].total_entries = 0;
        app_contexts[i].nr_cpus = nr_cpus;
        app_contexts[i].capture_duration = capture_duration;
        ret = pthread_attr_init(&thread_attrs[i]);
        if (ret < 0)
        {
            log_error("Failed to allocate thread attributes");
            goto out;
        }
        ret = pthread_create(&thread_ids[i], &thread_attrs[i], thread_poll, (void *)&app_contexts[i]);
        if (ret < 0)
        {
            log_error("Failed to create pthread %d", i);
            goto out;
        }
    }
    log_info("Thread (Main): Starting capture.");
    ret = bpf_map_update_elem(enb_fd, &map_index, &map_capture_value, 0);
    if (ret)
    {
        log_error("Thread (Main): bpf_map_update_elem 1 failed, %d", ret);
    }
    if (capture_duration)
    {
        capture_duration += THREAD_WARMUP_TIME;
        capture_duration *= NS_PER_SECOND;
        clock_gettime(CLOCK_MONOTONIC, &start);
        start_time = start.tv_sec * NS_PER_SECOND + start.tv_nsec;
    }

    while (running)
    {
        clock_gettime(CLOCK_MONOTONIC, &start);
        current_time = start.tv_sec * NS_PER_SECOND + start.tv_nsec;
        if (capture_duration && current_time - start_time >= capture_duration)
        {
            log_info("Thread (Main): Stopping capture.");
            ret = bpf_map_update_elem(enb_fd, &map_index, &map_idle_value, 0);
            if (ret)
            {
                log_error("Thread (Main): bpf_map_update_elem 0 <stop> failed, %d", ret);
            }
            capture_duration = 0;
            running = 0;
        }

        retrieve_and_print_stats_brief(stats_fd, &prev_calls);
        sleep(1);
    }
    for (i = 0; i < nr_cpus; i++)
    {
        pthread_join(thread_ids[i], NULL);
        total_entries += app_contexts[i].total_entries;
        log_info("Thread %d joined with %d entries", i, app_contexts[i].total_entries);
    }

    log_info("Thread (Main): Initializing Redis.");
    context = initialize_redis();
    if (context == NULL)
    {
        log_error("Thread (Main): Failed to initialize Redis.");
        goto out;
    }
    for (i = 0; i < nr_cpus; i++)
    {
        if (app_contexts[i].total_entries > 0)
        {
            log_info("Thread (%u) retrieved a total of %d entries", i, app_contexts[i].total_entries);

            ret = issue_commands(context, app_contexts[i].collected_entries, redis_key, app_contexts[i].total_entries);
            log_info("Thread (%u): transferred %u entries: %u commands ready to execute", i, app_contexts[i].total_entries, ret);
            total_commands += ret;
        }
    }
    if (total_commands > 0)
    {
        ret = flush_to_redis(context, total_commands);
        log_info("Executed %u / %u  commands. Exitting ...", ret, total_commands);
    }

out:
    log_info("All operations done. %d commands executed. %d entries stored. Exitting ...", total_commands, total_entries);
    retrieve_and_print_stats(stats_fd);
    free(thread_ids);
    free(thread_attrs);
    for (i = 0; i < nr_cpus; i++)
        free(app_contexts[i].collected_entries);
    free(app_contexts);

    return 0;
}
