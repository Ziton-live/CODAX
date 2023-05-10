#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>
#include "container_tracer.h"
#include <string.h>
#include "../commons.h"
#include <math.h>
#include "../_threshold_model/attack_threshold.h"

char LICENSE[]
SEC("license") = "Dual BSD/GPL";

// void __is_cont_list_exceed_threshold(int container_pids[], int containers_count);

bool _restrict_to_containers();

u64 __get_current_time();

u64 __get_cpu_time(u64 elapsed_time);


/**
 * @brief Checks whether the current process is running inside a container.
 *
 * Checks the name of the current executable file to determine whether
 * the process is running inside a container. 
 * @returns true if the process is containerized, 
 * @returns false otherwise.
 */
bool _restrict_to_containers() {
    char file_name[256];
    bpf_get_current_comm(&file_name, sizeof(file_name));
    if (__is_it_docker(file_name)) {
        return true;
    }
    return false;
}


/**
 * @brief BPF function that traces TCP connection accept system calls.
 *
 * This function traces the TCP connection accept system calls and stores the process ID
 * and start time of the process in a BPF hash map. If the process is running inside a
 * container, the information is stored in the hash map. Otherwise, the information is
 * discarded.
 *
 * @param ctx Pointer to the register context.
 * @return Always returns 0.
 */
SEC("kretprobe/tcp_v4_connect")

int __bpf_trace_accept_system_call(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    // bpf_printk("\n\nConnection From: %d\n", pid);
    u64 start_time = __get_current_time();
    if (_restrict_to_containers()) {
        bpf_printk("\n\nConnection From: %d\n", pid);
        bpf_map_update_elem(&proc_pid_start_time_hash_map, &pid, &start_time, BPF_ANY);
    }
    return 0;
}

/**
 * @brief BPF function that traces TCP connection close system calls.
 *
 * This function traces the TCP connection close system calls and calculates the elapsed
 * time between the connection start and end times if the process is running inside a
 * container. __is_cont_list_exceed_threshold checks for status of other containers. model_cpu_threshold to find the threshold/damage control
 *
 * @param ctx Pointer to the register context.
 * @return Always returns 0.
 */
SEC("kprobe/tcp_close")

int __bpf_trace_close_system_call(struct pt_regs *ctx) {
    if (_restrict_to_containers()) {
        int pid = bpf_get_current_pid_tgid() >> 32;
        // __is_cont_list_exceed_threshold(container_pids, containers_count);
        u64 *start_time = bpf_map_lookup_elem(&proc_pid_start_time_hash_map, &pid);
        u64 end_time = __get_current_time();
        if (start_time) {
            u64 elapsed_time = end_time - *start_time;
            model_cpu_threshold(__get_cpu_time(elapsed_time), pid);
        }

    }
    return 0;
}


// /**
//  * @brief Checks whether the number of container PIDs exceeds a threshold value.
//  *
//  * @param container_pids Array of container PIDs.
//  * @param containers_count Number of containers in the container_pids array.
//  */
// void __is_cont_list_exceed_threshold(int container_pids[], int containers_count) {
//     for (int i = 0; i < containers_count; i++) {
//         int a = 6912;
//         bpf_printk("containers : %d threshold:[%d]", a,
//                    bpf_map_lookup_elem(&proc_pid_threshold_hash_map, &a));
//     }
// }

/**
 * @brief Returns the elapsed time in CPU cycles.
 *
 * WARNING: This function should not be used in production as the elapsed time is wallclock time,
 * not CPU time. It is intended for debugging and testing purposes only.
 *
 * @param elapsed_time The elapsed time in nanoseconds.
 * @return The elapsed time in nanoseconds.
 */
u64 __get_cpu_time(u64 elapsed_time) {
    return elapsed_time;
}