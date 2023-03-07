#ifndef __gen_attack_threshold_H
#define __gen_attack_threshold_H
// #include "../commons.h";
#include <math.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct map_value {
    u64 n;
    u64 t_max;

    f64 mean;
    f64 std;
    f64 thresh;
}__attribute__((aligned(320), packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,
    int);
    __type(value, sizeof(struct map_value));
} thresh_maps
SEC(".maps");


void model_cpu_threshold(u64 elapsed_time, int pid) {
    bpf_printk("[%d] took %llu nano seconds\n: ", pid, elapsed_time);

    int k = 3;

    struct map_value def_val;
    def_val.thresh = 0;
    def_val.std = 0;
    def_val.mean = 0;
    def_val.t_max = 0;
    def_val.n = 0;

    struct map_value *value_ptr = bpf_map_lookup_elem_init(&thresh_maps, &pid, &def_val);


    u64 t_max = value_ptr->t_max;
    u64 n = value_ptr->n;
    f64 mean = value_ptr->mean;
    f64 std = value_ptr->std;
    f64 thresh = value_ptr->thresh;

    f64 temp_mean = mean;

    mean = (n * mean + elapsed_time) / n + 1;
    std = sqrt((n * pow(std, 2) + pow(elapsed_time - temp_mean, 2)) / (n + 1));

    f64 t = mean + k * std;

    thresh = t_max > t ? t_max : t;
    t_max = t_max > elapsed_time ? t_max : elapsed_time;
    n++;

    value_ptr->t_max = t_max;
    value_ptr->n = n;
    value_ptr->mean = mean;
    value_ptr->std = std;
    value_ptr->thresh = thresh;

    bpf_printk("%llu %llu %f %f %f\n: ", t_max, n, mean, std, thresh);

    bpf_map_update_elem(&exec_start, &pid, value_ptr, BPF_ANY);
}

#endif 