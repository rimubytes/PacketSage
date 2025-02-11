/**
 * @file softirqs.bpf.c
 * @brief eBPF program to monitor software interrupt (softirq) latency and count
 *
 * Software interrupts are kernel mechanisms for deferring work that's not critical
 * enough to be handled in hardware interrupt context. Common softirqs include:
 * - NET_TX/RX: Network transmit/receive processing
 * - TIMER: Timer-based events
 * - TASKLET: Tasklet processing
 * - BLOCK: Block device I/O
 * 
 * This program traces softirq entry/exit to measure:
 * - Number of times each type of softirq occurs
 * - Time spent processing each softirq (latency)
 * - Distribution of processing times (optional histogram)
 */

 #include <vmlinux.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include "softirqs.h"
 #include "bits.bpf.h"
 #include "maps.bpf.h"
 
 /* Configuration flags */
 const volatile bool targ_dist = false;  /* Enable latency distribution histogram */
 const volatile bool targ_ns = false;    /* Use nanoseconds (true) or microseconds (false) */
 
 /**
  * Per-CPU map to store softirq entry timestamps
  * Key: Always 0 (single entry per CPU)
  * Value: Timestamp in nanoseconds
  */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

/* Global statistics arrays (one entry per softirq type) */
__u64 counts[NR_SOFTIRQS] = {};     /* Count of softirq occurrences */
__u64 time[NR_SOFTIRQS] = {};       /* Cumulative processing time */
struct hist hists[NR_SOFTIRQS] = {}; /* Latency histograms */

/**
 * handle_entry - Common handler for softirq entry points
 * @vec_nr: Softirq vector number identifying the type
 * 
 * Records timestamp when a softirq begins processing.
 * 
 * @return 0 on success
 */