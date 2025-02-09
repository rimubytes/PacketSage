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
 
 /* Configuration flags */
 const volatile bool targ_dist = false;  /* Enable latency distribution histogram */
 const volatile bool targ_ns = false;    /* Use nanoseconds (true) or microseconds (false) */

