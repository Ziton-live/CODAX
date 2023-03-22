#ifndef __threshold_calculation_maps_H
#define __threshold_calculation_maps_H

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, unsigned int);
} proc_pid_request_count_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, unsigned int);
} proc_pid_mean_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, unsigned int);
} proc_pid_std_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, unsigned int);
} proc_pid_max_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, unsigned int);
} process_threshold_map SEC(".maps");


#endif