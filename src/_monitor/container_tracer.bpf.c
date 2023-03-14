#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <bpf/bpf_core_read.h>
#include <stdbool.h>
#include "container_tracer.h"
#include <string.h>
#include "../commons.h"
#include <math.h>


char LICENSE[]
SEC("license") = "Dual BSD/GPL";


u64 get_cpu_time(u64 elapsed_time);
void model_cpu_threshold(u64 elapsed_time, int pid);


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value, u64);
} pid_map SEC(".maps");





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


int THRESHOLD=4097191;

SEC("kretprobe/tcp_v4_connect")
int bpf_trace_accept_system_call(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    u64 start_time = get_current_time();
    
    if (restrict_to_test()) {
        bpf_map_update_elem(&pid_map, &pid, &start_time, BPF_ANY);
        bpf_printk("[Start Marker: %d %llu]\n",pid, start_time);
    }
    int pid_, zero = 0;
    
    return 0;
}



SEC("kprobe/tcp_close")
int bpf_trace_close_system_call(struct pt_regs *ctx) {
    int container_pids[]={39858,39879};
    if (restrict_to_test()) {

        int pid = bpf_get_current_pid_tgid() >> 32;
        u64 *start_time = bpf_map_lookup_elem(&pid_map, &pid);
        bpf_printk("Close Marker: %d\n", pid);
        for(int i = 0; i <2;i++) {
            if(container_pids[i] != pid){
                u64 *start_time = bpf_map_lookup_elem(&pid_map, &container_pids[i]);
                bpf_printk("Other container[%d]: %llu\n", container_pids[i],start_time);
                if(start_time) {
                    u64 end_time = get_current_time();
                    u64 elapsed_time = end_time - *start_time;
                    if(elapsed_time > THRESHOLD) {
                        bpf_printk("container[%d] having trouble: %llu\n", container_pids[i],start_time);
                    }
                }
            }
            
        }
        u64 end_time = get_current_time();
        if (start_time) {
            u64 elapsed_time = end_time - *start_time;
            model_cpu_threshold(get_cpu_time(elapsed_time), pid);
        }
    }
    return 0;
}


u64 get_cpu_time(u64 elapsed_time) {
    return elapsed_time;
}


void model_cpu_threshold(u64 elapsed_time, int pid) {
    if(elapsed_time > THRESHOLD){
        // bpf_printk("Attack: [%d] took %llu nano seconds operations[%llu]\n: ", pid, elapsed_time);
    }
    else{
        // bpf_printk("Normal: [%d] took %llu nano seconds operations[%llu]\n: ", pid, elapsed_time);
    }
}