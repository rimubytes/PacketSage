// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* 
 *
 * File Monitor BPF Program
 * ------------------------
 * This BPF program monitors file deletion operations by attaching to the
 * do_unlinkat system call. It logs the process ID and filename of files
 * being deleted, as well as the return status of the operation.
 */

#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* License declaration required by BPF verifier */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * Entry point for monitoring file deletion operations
 *
 * This function is called when the do_unlinkat system call is invoked.
 * do_unlinkat is used for deleting files and directories.
 *
 * @param dfd Directory file descriptor
 * @param name Pointer to the filename structure
 * @return Always returns 0
 */
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    // Get the current process ID (PID)
    // bpf_get_current_pid_tgid returns combined PID and TGID as u64
    // Right-shift by 32 to get only the PID part
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    
    // Extract the filename from the filename structure
    // BPF_CORE_READ is a helper macro for safe kernel memory access
    const char *filename = BPF_CORE_READ(name, name);
    
    // Log the process ID and filename to the kernel trace pipe
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    
    return 0;
}


SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    // Get the current process ID (PID)
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    
    // Log the process ID and return value to the kernel trace pipe
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    
    return 0;
}