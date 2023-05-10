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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event * e = data;

    FILE * fptr;
    char file_name[100];
//    sprintf(file_name, "/.codax/data/%d.thresh",e->threshold);
//    fptr = fopen(file_name, "w");
//    if(!fptr){
//        printf("The file is not opened.\n");
//        return 0;
//    }
    printf("%d", e->pid);
    return 0;
}

int main(int argc, char **argv)
{
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

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

    if(!PRODUCTION){
        printf("\n\033[93m[WARNING] PROGRAM STARTED IN DEBUG MODE (ONLY TRACING PYTHON TEST PROGRAMS) \n");
    }
	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	container_tracer_bpf__destroy(skel);
	return -err;
}
