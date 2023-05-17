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



bool _restrict_to_containers() {
    char file_name[256];
    bpf_get_current_comm(&file_name, sizeof(file_name));
    if (__is_it_docker(file_name)) {
        return true;
    }
    return false;
}

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

u64 __get_cpu_time(u64 elapsed_time) {
    return elapsed_time;
}



