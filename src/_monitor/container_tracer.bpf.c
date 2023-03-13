
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>
#include "container_tracer.h"
#include <string.h>
#include "../commons.h"
#include <math.h>
// #include "../_threshold_model/gen_attack_threshold.h"

char LICENSE[]
SEC("license") = "Dual BSD/GPL";

u64 get_cpu_time(u64 elapsed_time);

int model_cpu_threshold(u64 elapsed_time, int pid);

/**
    @struct pid_map
    @brief A hash map for storing key-value pairs, where the key is an integer representing a process ID and the value is also an integer.
    This map has a maximum of 8192 entries and is defined with the SEC(".maps") attribute for loading into the eBPF virtual machine.
    */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value, u64);
} pid_map
SEC(".maps");

u64 get_current_time() {
    return bpf_ktime_get_ns();

}

bool restrict_to_test() {
    if (PRODUCTION) return true;

    char file_name[256];
    bpf_get_current_comm(&file_name, sizeof(file_name));
    if (starts_with_python(file_name)) {
        /**
        @todo Find a a proper way to get the argument list of the python command
        use percpu memory instead of stack
        */

        // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        // char comm[TASK_COMM_LEN];
        // bpf_get_current_comm(&comm, sizeof(comm));
        // char *argp = (char *)task->mm->arg_start;
        // char *envp = (char *)task->mm->env_start;
        // int argc = task->mm->arg_end - task->mm->arg_start;
        // char buf[256];
        // bpf_probe_read_user(&buf, sizeof(buf), argp);
        bpf_printk("TCP Connection from: %s", file_name);
        return true;
    }

    return false;
}


/**
    @brief Entry point for BPF program to trace tcp packet receive
    kretprobe/tcp_v4_connect: for connecting with tcp packets.
    kprobe/__x64_sys_accept: for connecting with lo interface
    @param ctx A pointer to the pt_regs struct, which contains the register state at
    the time the BPF program was triggered.
    @return 0, indicating success.
*/
SEC("kretprobe/tcp_v4_connect")

int bpf_trace_accept_system_call(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    u64 start_time = get_current_time();

    if (restrict_to_test()) {
        bpf_map_update_elem(&pid_map, &pid, &start_time, BPF_ANY);
    }
    return 0;
}


/**
    @brief Entry point for BPF program that logs closed connections.
    This function is the entry point for a BPF program that logs when a process closes a network connection.
    It prints a message to the kernel log indicating the PID of the process that closed the connection.
    @param ctx A pointer to the pt_regs struct, which contains the register state at the time the BPF program
    was triggered.
    @return 0, indicating success.
    */
SEC("kprobe/tcp_close")

int bpf_trace_close_system_call(struct pt_regs *ctx) {
    if (restrict_to_test()) {

        int pid = bpf_get_current_pid_tgid() >> 32;
        u64 *start_time = bpf_map_lookup_elem(&pid_map, &pid);
        u64 end_time = get_current_time();
        if (start_time) {
            u64 elapsed_time = end_time - *start_time;
            model_cpu_threshold(get_cpu_time(elapsed_time), pid);
        }
    }
    return 0;
}

/**

    @brief Calculates the CPU time used for a given elapsed time.
    This function takes as input the elapsed. It is intended to be used to calculate the CPU time used by a process during the elapsed time.
    @warning Dont use this function as it is
    @param elapsed_time The elapsed time for which to calculate the CPU time.
    @return The same value as the input elapsed_time.
    */
u64 get_cpu_time(u64 elapsed_time) {
    return elapsed_time;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    int);
} n_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    int);
} mean_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    int);
} std_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    int);
} max_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    int);
} thresh_maps
SEC(".maps");


int model_cpu_threshold(u64 elapsed_time, int pid) {

    int *ptr = bpf_map_lookup_elem(&n_maps, &pid);
    if (!ptr) {
        int zero = 11;
        bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);
        bpf_map_update_elem(&n_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&mean_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&std_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&max_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&thresh_maps, &pid, &zero, BPF_ANY);
        return 0;
    }

    int *n = bpf_map_lookup_elem(&n_maps, &pid);
    int t_n;
    if (n) {
        t_n = *n;
    }

    int *mean = bpf_map_lookup_elem(&mean_maps, &pid);
    int t_mean;
    if (mean) {
        t_mean = *mean;
    }

    int *std = bpf_map_lookup_elem(&std_maps, &pid);
    int t_std;
    if (std) {
        t_std = *std;
    }

    int *max = bpf_map_lookup_elem(&max_maps, &pid);
    int t_max;
    if (max) {
        t_max = *max;
    }

    int *thresh = bpf_map_lookup_elem(&thresh_maps, &pid);
    int t_thresh;
    if (thresh) {
        t_thresh = *thresh;
    }

    int elapsed_t = 10;

    t_n++;
    t_mean++;
    t_std++;
    t_max++;
    t_thresh++;

//    value_ptr->std = 0; // (n * value_ptr->std * value_ptr->std + (elaspsed_t - value_ptr->mean) * (elaspsed_t - value_ptr->mean));
//    value_ptr->mean = (n * value_ptr->mean + elaspsed_t);

//    *mean = *n * *mean + elapsed_t;
//    *max = *max > elapsed_t ? *max : elapsed_t;
//    if (n)
//        *n = *n + 1;


//    int t = value_ptr->mean + 3 * value_ptr->std;
//
//    value_ptr->thresh = t_max > t ? t_max : t;
//    value_ptr->t_max = value_ptr->t_max > elaspsed_t ? value_ptr->t_max : elaspsed_t;
//
//    value_ptr->n = n + 1;

    bpf_printk("Elapsed Thresh = %d\n: ", *ptr);



    bpf_map_update_elem(&n_maps, &pid, &t_n, BPF_ANY);
    bpf_map_update_elem(&mean_maps, &pid, &t_mean, BPF_ANY);
    bpf_map_update_elem(&std_maps, &pid, &t_std, BPF_ANY);
    bpf_map_update_elem(&max_maps, &pid, &t_max, BPF_ANY);
    bpf_map_update_elem(&thresh_maps, &pid, &t_thresh, BPF_ANY);

    bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);

    return 0;

}