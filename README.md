# Valinor-H in-host traffic measurement framework

This eBPF program attempts to store timestamps in BPF maps and uses a control plane connected to Redis DB to store timestamp entries.

More information can be found at [in our NSDI paper](https://www.usenix.org/conference/nsdi23/presentation/sharafzadeh).

Also checkout [Valinor super repository](https://github.com/hopnets/valinor-artifacts).

Tested on Linnux kernel 5.15.

## Deployment steps

1. Install software requirements
    - build-essential flex bison libncurses5-dev
    - clang-10 llvm-10 gcc-multilib
    - libevent-dev
    - redis-server
    - libpci-dev
    - python3-pip
2. Dowmload and install the latest version of `dwarves` package for your distribution.
3. Compile and install the kernel 5.15 or higher with eBPF BTF functionalities enabled.
4. Run `git submodule init` and `git submodule update --recursive` to checkout three required repositories below. Then follow their installation steps.
5. Clone libbpf: `git clone https://github.com/libbpf/libbpf.git` (skip clone if running `submodule update`). Checkout to `v0.8.1`, build and install.
6. Clone IProute2: `git clone https://github.com/shemminger/iproute2.git`(skip clone if running `submodule update`). Checkout to `v5.18.0`. Build and install.
    - export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
    - make sure libbpf is added to pkgconfig: `pkg-config --list-all`
    - `./configure` and `make -j` and `make install`
    - You might need to link `libbpf` as follows in order to get tc to work: `sudo ln -s /usr/lib64/libbpf.so.0.8.1 /usr/lib/libbpf.so.0`
7. Clone, build, and install `hiredis` in `ext` subdirectory.
8. Modify you interfacce name in the `Makefile`.
9. Build Valinor-H:
    - build the data plane: `make`
    - build the control plane: `make control_plane`
10. Load and run: `sudo make run KEY={x}` where `x` is the Redis key for current run.


Every time you execute `make run` you should provide the key that will be used by Redis to store the timestamp items. This allows running multiple meausrements without unloading the dataplane. The measurement is triggered only when the control plane is running.

---------------


## Author
Erfan Sharafzadeh

2020-2023
