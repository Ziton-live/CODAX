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
} proc_pid_threshold_hash_map SEC(".maps");

/**
 * @brief A BPF hash map for storing process start times.
 *
 * integer key and an unsigned 64-bit value to store the start times
 * The maximum number of entries in the hash map is 8192.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, u64);
} proc_pid_start_time_hash_map SEC(".maps");


struct event{
    int pid;
    unsigned int threshold;
    unsigned int elapsed_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#endif