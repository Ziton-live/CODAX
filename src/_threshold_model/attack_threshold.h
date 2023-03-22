#ifndef __gen_attack_threshold_H
#define __gen_attack_threshold_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "threshold_calculation_maps.h"

void __initialize_maps(int pid) {
    int zero = 0;
    bpf_map_update_elem(&proc_pid_request_count_hash_map, &pid, &zero, BPF_ANY);
    bpf_map_update_elem(&proc_pid_mean_hash_map, &pid, &zero, BPF_ANY);
    bpf_map_update_elem(&proc_pid_std_hash_map, &pid, &zero, BPF_ANY);
    bpf_map_update_elem(&proc_pid_max_hash_map, &pid, &zero, BPF_ANY);
    bpf_map_update_elem(&proc_pid_threshold_hash_map, &pid, &zero, BPF_ANY);
}

unsigned int __get_value_from_map(struct bpf_map *map, int pid) {
    unsigned int *ptr = bpf_map_lookup_elem(map, &pid);
    if (ptr) {
        return *ptr;
    }
    return 0;
}

unsigned int _sqrt(unsigned int __val){
    unsigned int a = __val / 2;
    unsigned int b = (a + __val / a) / 2;

    for (int i = 0; i < 10; i++) {
        a = b;
        b = (a + __val / a) / 2;
    }
    return b;
}


int model_cpu_threshold(u64 elapsed_time, int pid) {

    unsigned int *ptr = bpf_map_lookup_elem(&proc_pid_request_count_hash_map, &pid);
    if (!ptr) {
        __initialize_maps(pid);
        return 0;
    }

    unsigned int elapsed_t = (unsigned int) (elapsed_time & 0xFFFFFFFF);;

    unsigned int request_count = __get_value_from_map((struct bpf_map *) &proc_pid_request_count_hash_map, pid);
    unsigned int mean_val = __get_value_from_map((struct bpf_map *) &proc_pid_mean_hash_map, pid);
    unsigned int std_val = __get_value_from_map((struct bpf_map *) &proc_pid_std_hash_map, pid);
    unsigned int max_val = __get_value_from_map((struct bpf_map *) &proc_pid_max_hash_map, pid);
    unsigned int threshold = __get_value_from_map((struct bpf_map *) &proc_pid_threshold_hash_map, pid);


    std_val = _sqrt(request_count * std_val * std_val + (elapsed_t - mean_val) * (elapsed_t - mean_val)) / (request_count + 1));


    mean_val = (request_count * mean_val + elapsed_t) / (request_count + 1);
    max_val = max_val > elapsed_t ? max_val : elapsed_t;

    unsigned int t = mean_val + 3 * std_val;
    threshold = max_val > t ? max_val : t;

    request_count++;

    bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);

    bpf_printk("Count = %d\n: ", request_count);
    bpf_printk("Mean = %d\n: ", mean_val);
    bpf_printk("Std = %d\n: ", std_val);
    bpf_printk("Max = %d\n: ", max_val);
    bpf_printk("Thresh = %d\n: ", threshold);
    bpf_printk("U64 = %d\n: ", elapsed_time);
    bpf_printk("U32 = %d\n: ", elapsed_t);


    bpf_map_update_elem(&proc_pid_request_count_hash_map, &pid, &request_count, BPF_ANY);
    bpf_map_update_elem(&proc_pid_mean_hash_map, &pid, &mean_val, BPF_ANY);
    bpf_map_update_elem(&proc_pid_std_hash_map, &pid, &std_val, BPF_ANY);
    bpf_map_update_elem(&proc_pid_max_hash_map, &pid, &max_val, BPF_ANY);
    bpf_map_update_elem(&proc_pid_threshold_hash_map, &pid, &threshold, BPF_ANY);

    return 0;

}

#endif 