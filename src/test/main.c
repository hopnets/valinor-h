#include <bpf/libbpf.h>
int main(int argc, char **argv) {
    bpf_program__set_autoload(NULL, false);
    bpf_map__ifindex(NULL);
    bpf_map__set_pin_path(NULL, NULL);
    bpf_object__open_file(NULL, NULL);
    return 0;
}