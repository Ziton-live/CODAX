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
    __type(key,
    int);
    __type(value, u64);
} pid_map SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, int);
    __type(value, long);
} my_array SEC(".maps");



u64 get_current_time() {
    return bpf_ktime_get_ns();

}

bool restrict_to_test() {
    if (PRODUCTION) return true;

    char file_name[256];
    bpf_get_current_comm(&file_name,sizeof(file_name));

    /**
        @todo Find a a proper way to distinguish container from non-docker processes.
    */
    if(is_it_docker(file_name)){
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
    int pid_, zero = 0;
    u32 index = 0;
    long *value;
    long value_ = 42;
    bpf_map_update_elem(&my_array, &index, &value_, BPF_ANY);
    value = bpf_map_lookup_elem(&my_array, &index);
    bpf_printk("[test]:%d\n",value);
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
    this 
    */
u64 get_cpu_time(u64 elapsed_time) {
    return elapsed_time;
}

struct map_value {
    double n;
    double t_max;

    double mean;
    double std;
    double thresh;
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
    if(elapsed_time > 4097191){
        // bpf_printk("Attack: [%d] took %llu nano seconds operations[%llu]\n: ", pid, elapsed_time);
    }
    else{
        // bpf_printk("Normal: [%d] took %llu nano seconds operations[%llu]\n: ", pid, elapsed_time);
    }
}