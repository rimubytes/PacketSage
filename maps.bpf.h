/**
 * @file maps.bpf.h
 * @brief Helper functions for eBPF map operations
 * 
 * This header provides utility functions for working with eBPF maps,
 * particularly focusing on common operations like atomic lookup-or-initialize
 * patterns that are frequently used in eBPF programs such as softirq monitoring.
 */

 #ifndef __MAPS_BPF_H
 #define __MAPS_BPF_H
 
 #include <bpf/bpf_helpers.h>
 #include <asm-generic/errno.h>

