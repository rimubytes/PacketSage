// Disable global data access for BPF programs
#define BPF_NO_GLOBAL_DATA

// Include necessary BPF headers
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Type definitions
typedef unsigned int u32;
typedef int pid_t;

// Configuration: Set to 0 to track all PIDs, or a specific PID to filter
#define PID_FILTER 0

// License declaration (required for BPF programs)
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF program attached to the sys_enter_write tracepoint
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    // Get the current process ID
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // If PID_FILTER is set and doesn't match the current PID, skip processing
    if (PID_FILTER && pid != PID_FILTER)
        return 0;

    // Log the triggered syscall with the process ID
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);

    return 0;
}