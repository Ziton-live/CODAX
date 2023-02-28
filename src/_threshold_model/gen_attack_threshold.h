#ifndef __gen_attack_threshold_H
#define __gen_attack_threshold_H
// #include "../commons.h";


void model_cpu_threshold(u64 elapsed_time,int pid){
    bpf_printk("[%d] took %llu nano seconds\n: ",pid,elapsed_time);
}

#endif 