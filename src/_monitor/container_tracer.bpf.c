
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>
#include "container_tracer.h"
#include <string.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";




/**
    @struct pid_map
    @brief A hash map for storing key-value pairs, where the key is an integer representing a process ID and the value is also an integer.
    This map has a maximum of 8192 entries and is defined with the SEC(".maps") attribute for loading into the eBPF virtual machine.
    */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, int);
} pid_map SEC(".maps");

u64 get_current_time(){
	u64 ts = bpf_ktime_get_ns();
	return ts;
}

bool restrict_to_test(){
    if(PRODUCTION) return true;
    
    char file_name[256];
    bpf_get_current_comm(&file_name,sizeof(file_name));
    if(starts_with_python(file_name)){
        bpf_printk("Opening file_name: %s",file_name);
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
int bpf_prog(struct pt_regs *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
    u64 start_time = get_current_time();
    
    if(restrict_to_test())
        bpf_map_update_elem(&pid_map, &pid,&start_time, BPF_ANY);
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
int bpf_prog2(struct pt_regs *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	// bpf_printk("Process closed connection %d\n: ",pid);
    return 0;
}


