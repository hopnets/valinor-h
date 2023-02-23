#include "cp_redis_handler.h"

#define TS_ARRAY "/sys/fs/bpf/tc/globals/ts_map"
#define TS_IDX "/sys/fs/bpf/tc/globals/idx_map"
#define STATS "/sys/fs/bpf/tc/globals/stat_map"
#define IFINDEX 4
#define LOG_BUFFER_SIZE 1024 * 1024
#define MAP_MAX_SIZE 1 << 24
enum { NS_PER_SECOND = 1000000000 };


int running = 1;

static void usage()
{
    printf("eBPF packet timestamping userspace control plane\n");
}

void graceful_exit(int signum){

  //Return type of the handler function should be void
  log_warn("SIGINT Caught!");
  running = 0;
}

void retrieve_and_print_stats(int stats_fd)
{
    int ret, successful, failed;
    const unsigned int stats_success = 0, stats_fail = 1;
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
    log_info("SUCCESSFUL CALLS: %d, FAILED CALLS: %d", successful, failed);
}

int main(int argc, char **argv)
{
    int ret, opt, i;
    int array_fd = -1;
    int idx_fd = -1;
    int stats_fd = -1;
    uint32_t read_index = 1;
    const unsigned int map_index = 0;
    const unsigned int map_index_value = 0;
    const unsigned int stats_success = 0, stats_fail = 1;
    struct timespec start;
    u_int64_t prev_value, prev_key = 0;
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    struct data_entry *values;
    struct app_context *app = (struct app_context*) malloc(sizeof(struct app_context));
    app->redis_key = 0;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    prev_value = start.tv_sec * NS_PER_SECOND + start.tv_nsec;

    log_info("Current timestamp is %lu", prev_value);

    values = (struct data_entry *) malloc(nr_cpus * sizeof(struct data_entry));

    if (argc > 2)
    {
        log_error("Too many arguments.");
        goto out;
    }
    else if (argc == 2)
    {
        app->redis_key = atoi(argv[1]);
    }

    log_info("Valinor: High-resolution traffic measurement framework");
    log_info("Redis key set to %u", app->redis_key);
    signal(SIGINT, graceful_exit); // Register signal handler
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
    stats_fd = bpf_obj_get(STATS);
    if (idx_fd < 0)
    {
        log_fatal("bpf_obj_get(%s): %s(%d)\n",
                  STATS, strerror(errno), errno);
        goto out;
    }
    log_info("Connected to stats store. Initializing");
    ret = bpf_map_update_elem(stats_fd, &stats_success, &map_index_value, 0);
    if (ret)
    {
        log_error("bpf_map_update_elem failed, %d", ret);
        goto out;
    }
    ret = bpf_map_update_elem(stats_fd, &stats_fail, &map_index_value, 0);
    if (ret)
    {
        log_error("bpf_map_update_elem failed, %d", ret);
        goto out;
    }

    app->collected_entries = (struct data_entry*) malloc(sizeof(struct data_entry)*1000000);
    if(app->collected_entries == NULL)
    {
        log_error("Failed to allocate entry array.");
        goto out;
    }

    log_info("Initializing Redis.");
    ret = initialize_redis(app);
    if(ret < 0)
    {
        log_error("Failed to initialize Redis.");
        goto out;
    }

    log_info("Starting poller ...");
    while (running)
    {

        // /* bpf_tunnel_key.remote_ipv4 expects host byte orders */
        // ret = bpf_map_lookup_elem(array_fd, &read_index, values);
        // if (ret)
        // {
        //     log_error("bpf_map_lookup_elem failed, %d", ret);
        //     goto out;
        // }
        // if (values[i].key != 0)
        // {
        //     // if(value.ts != prev_value || value.key != prev_key){    // we haven't read this value before!
        //         // log_info("retrieved value: lng=%lx, tst=%x, key=%x", values[i].ts, values[i].ts, values[i].key);
        //         memcpy(&app->collected_entries[read_index[i]-1], &values[i], sizeof(struct data_entry));
        //         prev_value = values[0].ts;
        //         prev_key = values[0].key;
        //         read_index[i]++;
        //         if(read_index[i] == MAP_MAX_SIZE)
        //         {
        //             log_info("resetting the read index");
        //             read_index[i] = 0;
        //             goto out;  // fixme
        //         }
        //     // }

        // }
        
    }

out:
    log_info("Closing eBPF descriptors");
    retrieve_and_print_stats(stats_fd);
    if (array_fd != -1)
        close(array_fd);
    if (read_index == 1)
        return 0;
    log_info("retrieved a total of %d entries", read_index);

    log_info("transferring to Redis ...");
    ret = issue_commands(app, c read_index);
    log_info("transferred %u entries: %u commands ready to execute", ret, app->commands);
    ret = flush_to_redis(app);
    log_info("Executed %u successful / %u unsuccessful commands. Exitting ...", ret, app->commands);
    return 0;
}