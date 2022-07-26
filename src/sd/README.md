# Measurement with Software-defined architecture

This variant attempts to store timestamps in BPF maps and uses a control plane connected to Redis to store timestamp entries.

Tested on kernel 5.15.

## Deployment steps
1. Install software requirements
    - build-essential flex bison libncurses5-dev
    - clang-10 llvm-10 gcc-multilib
    - libevent-dev
    - redis-server
    - libpci-dev
    - python3-pip
2. Dowmload and install the latest version of `dwarves` package. A `deb` archive is provided in the repository.
3. Copy the provided `linux.config` as `.config` in kernel source. Compile and install the kernel.
4. Clone libbpf: `git clone https://github.com/libbpf/libbpf.git`. Checkout to `v0.8.1`, build and install.
5. Clone IProute2: `git clone https://github.com/shemminger/iproute2.git`. Checkout to `v5.18.0`. Build and install.
    - export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
    - make sure libbpf is added to pkgconfig: `pkg-config --list-all`
    - `./configure` and `make -j` and `make install`
    - You might need to link `libbpf` as follows in order to get tc to work: `sudo ln -s /usr/lib64/libbpf.so.0.8.1 /usr/lib/libbpf.so.0`
6. Clone, build, and install `hiredis` in `ext` subdirectory.
7. Build the `sd` directory.
    - build the data plane: `make`
    - build the control plane: `make control_plane`
8. Load and run: `sudo make run KEY={x}` where `x` is the Redis key for current run.
