#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "container_tracer.skel.h"
#include "container_tracer.h"
#include "../commons.h"
//#include "../_threshold_model/threshold_calculation_maps.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo) {
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;

    if(!e) return 0;

//    if(e->probable_DoS){
//    }

    FILE *fptr;
    char thresh_file_name[100];
    sprintf(thresh_file_name, "/.codax/data/%d.thresh", e->pid);
    fptr = fopen(thresh_file_name, "w");
    if (!fptr) {
        printf("The file is not opened.\n");
        return 0;
    }
    fprintf(fptr, "%u", e->threshold);
    fclose(fptr);

    char time_file_name[100];
    sprintf(time_file_name, "/.codax/data/%d.txt", e->pid);
    fptr = fopen(time_file_name, "a");
    if (!fptr) {
        printf("The file is not opened.\n");
        return 0;
    }
    fprintf(fptr, "%u\n", e->elapsed_time);
    fclose(fptr);

    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct container_tracer_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open load and verify BPF application */
    skel = container_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoint handler */
    err = container_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    if (!PRODUCTION) {
        printf("\n\033[93m[WARNING] PROGRAM STARTED IN DEBUG MODE (ONLY TRACING PYTHON TEST PROGRAMS) \n");
    }
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    cleanup:
    container_tracer_bpf__destroy(skel);
    return -err;
}
