
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

void model_cpu_threshold(u64 elapsed_time, int pid);

/**
    @struct pid_map
    @brief A hash map for storing key-value pairs, where the key is an integer representing a process ID and the value is also an integer.
    This map has a maximum of 8192 entries and is defined with the SEC(".maps") attribute for loading into the eBPF virtual machine.
    */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
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

struct map_value {
    int n;
    int t_max;
    int mean;
    int std;
    int thresh;
}__attribute__((aligned(64), packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value, sizeof(struct map_value));
} thresh_maps
SEC(".maps");


void model_cpu_threshold(u64 elapsed_time, int pid) {
//    bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);

    struct map_value def_val;
    def_val.std = 0;
    def_val.mean = 0;
    def_val.t_max = 0;
    def_val.n = 0;

    struct map_value *value_ptr = bpf_map_lookup_elem(&thresh_maps, &pid);

    if (!value_ptr) {
        value_ptr = &def_val;
    }

    int t_max = value_ptr->t_max;
    int n = value_ptr->n;

    int elaspsed_t = 10;


    value_ptr->std = 0 // (n * value_ptr->std * value_ptr->std + (elaspsed_t - value_ptr->mean) * (elaspsed_t - value_ptr->mean));
    value_ptr->mean = (n * value_ptr->mean + elaspsed_t);


    int t = value_ptr->mean + 3 * value_ptr->std;

    value_ptr->thresh = t_max > t ? t_max : t;
    value_ptr->t_max = value_ptr->t_max > elaspsed_t ? value_ptr->t_max : elaspsed_t;

    value_ptr->n = n + 1;

    bpf_printk("Elapsed Thresh = %f\n: ", value_ptr->thresh);

    bpf_map_update_elem(&thresh_maps, &pid, value_ptr, BPF_ANY);
}