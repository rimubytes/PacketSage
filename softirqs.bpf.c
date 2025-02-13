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

static int handle_entry(unsigned int vec_nr)
{
    u64 ts = bpf_ktime_get_ns();
    u32 key = 0;

    /* Store entry timestamp in per-CPU array */
    bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    return 0;
}

/**
 * handle_exit - Common handler for softirq exit points
 * @vec_nr: Softirq vector number identifying the type
 * 
 * Calculates softirq processing time and updates statistics.
 * Can either store raw timing data or update a log2 histogram
 * of processing times.
 * 
 * @return 0 on success, error code on invalid vector number
 */

static int handle_exit(unsigned int vec_nr)
{
    u64 delta, *tsp;
    u32 key = 0;

    /* Validate softirq vector number */
    if (vec_nr >= NR_SOFTIRQS)
        return 0;

    /* Get entry timestamp */
    tsp = bpf_map_lookup_elem(&start, &key);
    if (!tsp)
        return 0;

            /* Calculate processing time */
    delta = bpf_ktime_get_ns() - *tsp;
    if (!targ_ns)
        delta /= 1000U;  /* Convert to microseconds if requested */

    if (!targ_dist) {
        /* Update count and total time atomically */
        __sync_fetch_and_add(&counts[vec_nr], 1);
        __sync_fetch_and_add(&time[vec_nr], delta);
    } else {
        /* Update latency histogram */
        struct hist *hist = &hists[vec_nr];
        u64 slot = log2(delta);

        /* Clamp to maximum slot */
        if (slot >= MAX_SLOTS)
            slot = MAX_SLOTS - 1;

        /* Increment histogram slot atomically */
        __sync_fetch_and_add(&hist->slots[slot], 1);
    }

    return 0;
}
