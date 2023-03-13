#ifndef __gen_attack_threshold_H
#define __gen_attack_threshold_H
// #include "../commons.h";
#include <math.h>
//#include "vmlinux.h"
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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

    double t_max = value_ptr->t_max;
    double n = value_ptr->n;

    double elaspsed_t = 10;

    value_ptr->std = (n * value_ptr->std * value_ptr->std + (elaspsed_t - value_ptr->mean) * (elaspsed_t - value_ptr->mean)) / (n + 1);
    value_ptr->mean = (n * value_ptr->mean + elaspsed_t) / n + 1;


    double t = value_ptr->mean + 3 * value_ptr->std;

    value_ptr->thresh = t_max > t ? t_max : t;
    value_ptr->t_max = value_ptr->t_max > elaspsed_t ? value_ptr->t_max : elaspsed_t;

    value_ptr->n = n + 1;

    bpf_printk("Elapsed Thresh = %f\n: ", value_ptr->thresh);

    bpf_map_update_elem(&thresh_maps, &pid, value_ptr, BPF_ANY);
}

#endif 