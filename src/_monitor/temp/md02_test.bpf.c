
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "net/sock.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, int);
} pid_map SEC(".maps");

// To trace all system calls in TCP
// SEC("kprobe/__x64_sys_accept") for lo

u64 get_current_time(){
	u64 ts = bpf_ktime_get_ns();
	return ts;
}
// SEC("kprobe/tcp_v4_do_rcv")
// SEC("kprobe/__x64_sys_accept")
// SEC("kprobe/tcp_v4_do_rcv")
// SEC("kprobe/inet_csk_accept")
SEC("kprobe/__x64_sys_accept")
/**
@param *ctx structure
@return 0 on success 
 */
int bpf_prog(struct pt_regs *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
    u64 start_time = get_current_time();
	bpf_printk("BPF triggered from PID %d.\n", pid);
    bpf_map_update_elem(&pid_map, &pid,&start_time, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_close")
int bpf_prog2(struct pt_regs *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	u64 *pid_ptr = bpf_map_lookup_elem(&pid_map, &pid);
	
    if (pid_ptr != NULL && *pid_ptr == pid && *pid_ptr>100ULL) {
        bpf_printk("Process closed connection %d\n: ",pid);
    }

    // bpf_trace_printk("tcp_close called\n");
    return 0;
}


