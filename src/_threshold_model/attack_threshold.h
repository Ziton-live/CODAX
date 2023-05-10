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

/**
 * @brief Gets the current time in nanoseconds since system boot.
 *
 * @return The current time in nanoseconds since system boot.
 */
u64 __get_current_time() {
    return bpf_ktime_get_ns();
}

int __pids[10] = {0};

void __add_pids(int pid) {
    for (int i = 0; i < 10; i++) {
        if (__pids[i] == pid) return;
        if (__pids[i] == 0) {
            __pids[i] = pid;
            return;
        }
    }
}

void __is_cont_list_exceed_threshold() {
    for (int i = 0; i < 10; i++) {
        if (__pids[i] == 0) return;
        unsigned int threshold = __get_value_from_map((struct bpf_map *) &proc_pid_threshold_hash_map, __pids[i]);
        bpf_printk("Threshold(%d) = %i\n: ", __pids[i], threshold);
        u64 *start_time = bpf_map_lookup_elem(&proc_pid_start_time_hash_map, &__pids[i]);
        u64 end_time = __get_current_time();
        bpf_printk("Start Time %llu", *start_time);
//        if(start_time){
//            u64 elapsed_time = end_time - *start_time;
//            unsigned int st = (unsigned int) (elapsed_time & 0xFFFFFFFF);
//            if(st > threshold){
//                bpf_printk("Probable DOS %i\n: ", __pids[i]);
//
//            }
//        }
    }
}

unsigned int _sqrt(unsigned int __val) {
    unsigned int a = __val / 2;
    unsigned int b = (a + __val / a) / 2;

    for (int i = 0; i < 10; i++) {
        a = b;
        b = (a + __val / a) / 2;
    }
    return b;
}

void __production(unsigned int elapsed_t, int pid) {
    unsigned int threshold = __get_value_from_map((struct bpf_map *) &proc_pid_threshold_hash_map, pid);
    if (threshold < elapsed_t) {
        bpf_printk("Violated Thresh = %u | %u\n: ", threshold, elapsed_t);
    } else {
        bpf_printk("Normal Thresh = %u | %u\n: ", threshold, elapsed_t);
    }
    __is_cont_list_exceed_threshold();
}


int model_cpu_threshold(u64 elapsed_time, int pid) {

    unsigned int *ptr = bpf_map_lookup_elem(&proc_pid_request_count_hash_map, &pid);
    if (!ptr) {
        __initialize_maps(pid);
        return 0;
    }

    unsigned int elapsed_t = (unsigned int) (elapsed_time & 0xFFFFFFFF);

    if (*ptr > 1000) {
        __production(elapsed_t, pid);
        return 0;
    }

    unsigned int request_count = __get_value_from_map((struct bpf_map *) &proc_pid_request_count_hash_map, pid);
    unsigned int mean_val = __get_value_from_map((struct bpf_map *) &proc_pid_mean_hash_map, pid);
    unsigned int std_val = __get_value_from_map((struct bpf_map *) &proc_pid_std_hash_map, pid);
    unsigned int max_val = __get_value_from_map((struct bpf_map *) &proc_pid_max_hash_map, pid);
    unsigned int threshold = __get_value_from_map((struct bpf_map *) &proc_pid_threshold_hash_map, pid);

    bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);

    bpf_printk("Count = %u\n: ", request_count);
//    bpf_printk("Mean = %i\n: ", mean_val);
//    bpf_printk("Std = %i\n: ", std_val);
//    bpf_printk("Max = %i\n: ", max_val);
    bpf_printk("Thresh = %u\n: ", threshold);
//    bpf_printk("U64 = %i\n: ", elapsed_time);
//    bpf_printk("U32 = %i\n: ", elapsed_t);


    std_val = _sqrt((request_count * std_val * std_val + (elapsed_t - mean_val) * (elapsed_t - mean_val)) /
                    (request_count + 1));


    mean_val = (request_count * mean_val + elapsed_t) / (request_count + 1);
    max_val = max_val > elapsed_t ? max_val : elapsed_t;

    unsigned int t = mean_val + 3 * std_val;
    threshold = max_val > t ? max_val : t;

    request_count++;


    bpf_map_update_elem(&proc_pid_request_count_hash_map, &pid, &request_count, BPF_ANY);
    bpf_map_update_elem(&proc_pid_mean_hash_map, &pid, &mean_val, BPF_ANY);
    bpf_map_update_elem(&proc_pid_std_hash_map, &pid, &std_val, BPF_ANY);
    bpf_map_update_elem(&proc_pid_max_hash_map, &pid, &max_val, BPF_ANY);
    bpf_map_update_elem(&proc_pid_threshold_hash_map, &pid, &threshold, BPF_ANY);
    __add_pids(pid);
    return 0;
}


#endif