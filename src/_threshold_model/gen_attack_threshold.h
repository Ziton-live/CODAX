#ifndef __gen_attack_threshold_H
#define __gen_attack_threshold_H
// #include "../commons.h";
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    unsigned int);
} n_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    unsigned int);
} mean_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    unsigned int);
} std_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    unsigned int);
} max_maps
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value,
    unsigned int);
} proc_pid_threshold_hash_map
SEC(".maps");


int model_cpu_threshold(u64 elapsed_time, int pid) {

    unsigned int *ptr = bpf_map_lookup_elem(&n_maps, &pid);
    if (!ptr) {
        int zero = 0;
        bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);
        bpf_map_update_elem(&n_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&mean_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&std_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&max_maps, &pid, &zero, BPF_ANY);
        bpf_map_update_elem(&proc_pid_threshold_hash_map, &pid, &zero, BPF_ANY);
        return 0;
    }

    unsigned int *n = bpf_map_lookup_elem(&n_maps, &pid);
    unsigned int t_n = 0;
    if (n) {
        t_n = *n;
    }

    unsigned int *mean = bpf_map_lookup_elem(&mean_maps, &pid);
    unsigned int t_mean = 0;
    if (mean) {
        t_mean = *mean;
    }

    unsigned int *std = bpf_map_lookup_elem(&std_maps, &pid);
    unsigned int t_std = 0;
    if (std) {
        t_std = *std;
    }

    unsigned int *max = bpf_map_lookup_elem(&max_maps, &pid);
    unsigned int t_max = 0;
    if (max) {
        t_max = *max;
    }

    unsigned int *thresh = bpf_map_lookup_elem(&proc_pid_threshold_hash_map, &pid);
    unsigned int t_thresh = 0;
    if (thresh) {
        t_thresh = *thresh;
    }

    unsigned int elapsed_t = (unsigned int) (elapsed_time & 0xFFFFFFFF);;

    t_std = (t_n * t_std * t_std + (elapsed_t - t_mean) * (elapsed_t - t_mean)) / (t_n + 1);

    //sqrt
    unsigned int a = t_std / 2;
    unsigned int b = (a + t_std / a) / 2;

    for (int i = 0; i < 10; i++) {
        a = b;
        b = (a + t_std / a) / 2;
    }
    t_std = b;

    t_mean = (t_n * t_mean + elapsed_t) / (t_n + 1);
    t_max = t_max > elapsed_t ? t_max : elapsed_t;

    unsigned int t = t_mean + 3 * t_std;
    t_thresh = t_max > t ? t_max : t;

    t_n++;

    // bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);

    // bpf_printk("Count = %d\n: ", t_n);
    // bpf_printk("Mean = %d\n: ", t_mean);
    // bpf_printk("Std = %d\n: ", t_std);
    // bpf_printk("Max = %d\n: ", t_max);
    // bpf_printk("Thresh = %d\n: ", t_thresh);
    // bpf_printk("U64 = %d\n: ", elapsed_time);
    // bpf_printk("U32 = %d\n: ", elapsed_t);


    bpf_map_update_elem(&n_maps, &pid, &t_n, BPF_ANY);
    bpf_map_update_elem(&mean_maps, &pid, &t_mean, BPF_ANY);
    bpf_map_update_elem(&std_maps, &pid, &t_std, BPF_ANY);
    bpf_map_update_elem(&max_maps, &pid, &t_max, BPF_ANY);
    bpf_map_update_elem(&proc_pid_threshold_hash_map, &pid, &t_thresh, BPF_ANY);

    return 0;

}

#endif 