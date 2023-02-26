#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "net/sock.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} pid_map SEC(".maps");

// To trace all system calls in TCP
// SEC("kprobe/__x64_sys_accept") for lo

u64 get_current_time(){
	u64 ts = bpf_ktime_get_ns();
	return ts;
}
//SEC("kprobe/tcp_v4_connect")
SEC("kretprobe/tcp_v4_connect")
// SEC("kprobe/__x64_sys_accept")
//SEC("kprobe/tcp_v4_do_rcv")
//SEC("kprobe/inet_csk_accept")
//SEC("kprobe/__x64_sys_accept")
/**
@param *ctx structure
@return 0 on success 
 */
int bpf_prog(struct pt_regs *ctx)
{
	pid_t pid, tid;
	u64 id;
	
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
	
        u64 start_time = get_current_time();
        
        if(pid!=tid){
        	bpf_map_update_elem(&pid_map, &tid,&start_time, BPF_ANY);
        	//bpf_printk("BPF triggered from TID %d\n", tid);
	}
	
	bpf_printk("BPF triggered from PID %d\n", pid);
        bpf_map_update_elem(&pid_map, &pid,&start_time, BPF_ANY);
        return 0;
}

SEC("kprobe/tcp_close")
int bpf_prog2(struct pt_regs *ctx)
{       
        struct task_struct *task;
	pid_t pid, tid,ppid;
	u64 id, *pid_ptr, duration_ns = 0;
	
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
	
	task = (struct task_struct *)bpf_get_current_task();
	
	ppid = BPF_CORE_READ(task, real_parent, tgid);
	pid_ptr = bpf_map_lookup_elem(&pid_map, &pid);
	
	if (pid_ptr ) {
		duration_ns = bpf_ktime_get_ns() - *pid_ptr;
		bpf_printk("Process closed connection %d and duration is %d\n",pid,duration_ns);
	}
	
        if (pid_ptr != NULL && *pid_ptr == pid && *pid_ptr>100ULL) {
        	//bpf_printk("Process closed connection %d at %ld\n",pid,duration_ns);
        }

    // bpf_trace_printk("tcp_close called\n");
    return 0;
}
