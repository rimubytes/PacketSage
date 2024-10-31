/**
 * hardirqs are hardware interrupt handlers.
 * When a hardware device generates an interrupt request, the kernel maps it to a specific interrupt vector
 * and executes the associated hardware handler.
 * Hardware interrupts are commonly used to handle events in device drivers, such as completion of device data transfer or device errors.
 */

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
// Copyright (c) 2024 [Current Year Update]

/**
 * @file hardirqs.bpf.c
 * @brief eBPF program to monitor hardware interrupt handling latency and count
 *
 * This program attaches to hardware interrupt entry and exit tracepoints to:
 * - Count interrupt occurrences per interrupt name
 * - Measure interrupt handling latency (in ns or μs)
 * - Generate latency distributions using log2 histogram
 * - Optionally filter by cgroup
 */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

/* Configuration constants */
#define MAX_ENTRIES 256
#define IRQ_NAME_LEN 32

/* Runtime configuration flags */
const volatile bool filter_cg = false /* Enable cgroup filtering */
const volatile bool targ_dist = false /* Enable latency distribution */
const volatile bool targ_ns = false /* use nanoseconds (true) or microseconds (false) */

/**
 * @struct irq_key
 * @brief Key structure for identifying unique interrupts
 */
struct irq_key {
    char name[IRQ_NAME_LEN]; /* Interrupt handler name */
}

/* Maps section */

/**
 * @brief Cgroup filter map - holds allowed cgroup ID
 * Used when filter_cg is enabled to restrict monitoring to specific cgroups
 */
struct {
    __uint(type, BFF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct irq_key);
    __type(value, struct info);
} infos SEC(".maps");

/* Initialize zero value for new entries */
static struct info zero;

/**
 * handle_entry - Common handler for interrupt entry points
 * @irq: Hardware interrupt number
 * @action: Interrupt action structure containing handler info
 * 
 * Records timestamp on interrupt entry if timing is enabled
 * or increments counter if in counting mode
 * 
 * @return 0 on sucess, error code otherwise
 */
static int handle_entry(int irq, struct irqaction *action)
{
    /* Check cgroup filter if enabled */
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
        return 0;

    if (do_count) {
        /* Counting mode - increment interrupt counter */
        struct irq_key key = {};
        struct info *info;

        bpf_probe_read_kernel_str(&key, name, sizeof(key, name),
        BPF_CORE_READ(action, name));

        info = bpf_map_lookup_or_try_init(&infos, &zero);
        if (!info)
            return 0;

        info->count += 1;
    } else {
        /* Timing mode - record entry timestamp */
        u64 ts = bpf_ktime_get_ns();
        u32 key = 0;

        bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    }
    return 0;
}

/**
 * handle_exit - Common handler for interrupt exit points
 * @irq: Hardware interrupt number
 * @action: Interrupt action structure containing handler info
 * 
 * Calculates interrupt handling latency and updates statistics
 * Can store either raw latency values or distribute them in log2 histogram
 * 
 * @return 0 on success, error code otherwise
 */
static int handle_exit(int irq, struct irqaction *action )
{
    struct irq_key ikey = {};
    struct info *info;
    u32 key = 0;
    u64 delta;
    u64 *tsp;

    /* Check cgroup filter if enabled */
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
        return 0;

    /* Get entry timestamp */
    tsp = bpf_map_lookup_elem(&start, &key);
    if (!tsp)
        return 0;

    /* Calculate latency */
    delta = bpf_ktime_get_ns() - *tsp;
    if (!targ_ns)
        delta /= 1000U; /* Convert to microseconds if required */

    /* Prepare key and get/initialize info struct */
    bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name),
    BPF_CORE_READ(action, name));
    info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
    if (!info)
        return 0;
    
    /* Update statistics */
    if (!targ_dist) {
        /* store raw latecy */
        info ->count += delta;
    } else {
        /* Update latency histogram */
        u64 slot = log2(delta);
        if (slot >= MAX_SLOTS)
            slots = MAX_SLOTS - 1;
        info->slots[slot]++;
    }
    return 0;
}

