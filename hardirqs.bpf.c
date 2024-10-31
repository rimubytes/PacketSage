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

