/* This file was generated from libbpf. See https://github.com/libbpf/libbpf */
/* It was manually trimmed after its generation. */

/* Forward declarations of BPF structs */
struct __sk_buff;

/*
 * bpf_trace_printk
 *
 *      This helper is a "printk()-like" facility for debugging. It
 *      prints a message defined by format *fmt* (of size *fmt_size*)
 *      to file *\/sys/kernel/debug/tracing/trace* from DebugFS, if
 *      available. It can take up to three additional **u64**
 *      arguments (as an eBPF helpers, the total number of arguments is
 *      limited to five).
 *
 *      Each time the helper is called, it appends a line to the trace.
 *      Lines are discarded while *\/sys/kernel/debug/tracing/trace* is
 *      open, use *\/sys/kernel/debug/tracing/trace_pipe* to avoid this.
 *      The format of the trace is customizable, and the exact output
 *      one will get depends on the options set in
 *      *\/sys/kernel/debug/tracing/trace_options* (see also the
 *      *README* file under the same directory). However, it usually
 *      defaults to something like:
 *
 *      ::
 *
 *              telnet-470   [001] .N.. 419421.045894: 0x00000001: <formatted msg>
 *
 *      In the above:
 *
 *              * ``telnet`` is the name of the current task.
 *              * ``470`` is the PID of the current task.
 *              * ``001`` is the CPU number on which the task is
 *                running.
 *              * In ``.N..``, each character refers to a set of
 *                options (whether irqs are enabled, scheduling
 *                options, whether hard/softirqs are running, level of
 *                preempt_disabled respectively). **N** means that
 *                **TIF_NEED_RESCHED** and **PREEMPT_NEED_RESCHED**
 *                are set.
 *              * ``419421.045894`` is a timestamp.
 *              * ``0x00000001`` is a fake value used by BPF for the
 *                instruction pointer register.
 *              * ``<formatted msg>`` is the message formatted with
 *                *fmt*.
 *
 *      The conversion specifiers supported by *fmt* are similar, but
 *      more limited than for printk(). They are **%d**, **%i**,
 *      **%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**,
 *      **%lli**, **%llu**, **%llx**, **%p**, **%s**. No modifier (size
 *      of field, padding with zeroes, etc.) is available, and the
 *      helper will return **-EINVAL** (but print nothing) if it
 *      encounters an unknown specifier.
 *
 *      Also, note that **bpf_trace_printk**\ () is slow, and should
 *      only be used for debugging purposes. For this reason, a notice
 *      block (spanning several lines) is printed to kernel logs and
 *      states that the helper should not be used "for production use"
 *      the first time this helper is used (or more precisely, when
 *      **trace_printk**\ () buffers are allocated). For passing values
 *      to user space, perf events should be preferred.
 *
 * Returns
 *      The number of bytes written to the buffer, or a negative error
 *      in case of failure.
 */
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;

/*
 * bpf_skb_store_bytes
 *
 *      Store *len* bytes from address *from* into the packet
 *      associated to *skb*, at *offset*. *flags* are a combination of
 *      **BPF_F_RECOMPUTE_CSUM** (automatically recompute the
 *      checksum for the packet after storing the bytes) and
 *      **BPF_F_INVALIDATE_HASH** (set *skb*\ **->hash**, *skb*\
 *      **->swhash** and *skb*\ **->l4hash** to 0).
 *
 *      A call to this helper is susceptible to change the underlying
 *      packet buffer. Therefore, at load time, all checks on pointers
 *      previously done by the verifier are invalidated and must be
 *      performed again, if the helper is used in combination with
 *      direct packet access.
 *
 * Returns
 *      0 on success, or a negative error in case of failure.
 */
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *) 9;

/*
 * bpf_l3_csum_replace
 *
 *      Recompute the layer 3 (e.g. IP) checksum for the packet
 *      associated to *skb*. Computation is incremental, so the helper
 *      must know the former value of the header field that was
 *      modified (*from*), the new value of this field (*to*), and the
 *      number of bytes (2 or 4) for this field, stored in *size*.
 *      Alternatively, it is possible to store the difference between
 *      the previous and the new values of the header field in *to*, by
 *      setting *from* and *size* to 0. For both methods, *offset*
 *      indicates the location of the IP checksum within the packet.
 *
 *      This helper works in combination with **bpf_csum_diff**\ (),
 *      which does not update the checksum in-place, but offers more
 *      flexibility and can handle sizes larger than 2 or 4 for the
 *      checksum to update.
 *
 *      A call to this helper is susceptible to change the underlying
 *      packet buffer. Therefore, at load time, all checks on pointers
 *      previously done by the verifier are invalidated and must be
 *      performed again, if the helper is used in combination with
 *      direct packet access.
 *
 * Returns
 *      0 on success, or a negative error in case of failure.
 */
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *) 10;

/*
 * bpf_csum_diff
 *
 *      Compute a checksum difference, from the raw buffer pointed by
 *      *from*, of length *from_size* (that must be a multiple of 4),
 *      towards the raw buffer pointed by *to*, of size *to_size*
 *      (same remark). An optional *seed* can be added to the value
 *      (this can be cascaded, the seed may come from a previous call
 *      to the helper).
 *
 *      This is flexible enough to be used in several ways:
 *
 *      * With *from_size* == 0, *to_size* > 0 and *seed* set to
 *        checksum, it can be used when pushing new data.
 *      * With *from_size* > 0, *to_size* == 0 and *seed* set to
 *        checksum, it can be used when removing data from a packet.
 *      * With *from_size* > 0, *to_size* > 0 and *seed* set to 0, it
 *        can be used to compute a diff. Note that *from_size* and
 *        *to_size* do not need to be equal.
 *
 *      This helper can be used in combination with
 *      **bpf_l3_csum_replace**\ () and **bpf_l4_csum_replace**\ (), to
 *      which one can feed in the difference computed with
 *      **bpf_csum_diff**\ ().
 *
 * Returns
 *      The checksum result, or a negative error code in case of
 *      failure.
 */
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) = (void *) 28;

/*
 * bpf_skb_pull_data
 *
 *      Pull in non-linear data in case the *skb* is non-linear and not
 *      all of *len* are part of the linear section. Make *len* bytes
 *      from *skb* readable and writable. If a zero value is passed for
 *      *len*, then the whole length of the *skb* is pulled.
 *
 *      This helper is only needed for reading and writing with direct
 *      packet access.
 *
 *      For direct packet access, testing that offsets to access
 *      are within packet boundaries (test on *skb*\ **->data_end**) is
 *      susceptible to fail if offsets are invalid, or if the requested
 *      data is in non-linear parts of the *skb*. On failure the
 *      program can just bail out, or in the case of a non-linear
 *      buffer, use a helper to make the data available. The
 *      **bpf_skb_load_bytes**\ () helper is a first solution to access
 *      the data. Another one consists in using **bpf_skb_pull_data**
 *      to pull in once the non-linear parts, then retesting and
 *      eventually access the data.
 *
 *      At the same time, this also makes sure the *skb* is uncloned,
 *      which is a necessary condition for direct write. As this needs
 *      to be an invariant for the write part only, the verifier
 *      detects writes and adds a prologue that is calling
 *      **bpf_skb_pull_data()** to effectively unclone the *skb* from
 *      the very beginning in case it is indeed cloned.
 *
 *      A call to this helper is susceptible to change the underlying
 *      packet buffer. Therefore, at load time, all checks on pointers
 *      previously done by the verifier are invalidated and must be
 *      performed again, if the helper is used in combination with
 *      direct packet access.
 *
 * Returns
 *      0 on success, or a negative error in case of failure.
 */
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *) 39;
