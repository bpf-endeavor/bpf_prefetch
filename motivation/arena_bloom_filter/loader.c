// vim: et sw=4 ts=4:
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <assert.h>

#include <linux/if_link.h> // XDP_FLAGS_*

#include "include/compiler.h"
#include <bpf/bpf.h>

#include "include/shared_struct.h"
#include "baseline.skel.h"

typedef enum {
    BASELINE,
    ARENA,
} prog_t;

/* Some global vars */
static char *ifacename;
static int ifindex;
static int xdp_flags;
static prog_t selected_prog;
static volatile int running = 0;

static void handle_signal(int s)
{
    running = 0;
}

static void usage(void)
{
    printf("Usage: prog OPTIONS\n"
           "OPTIONS:\n"
           "\t--arena: use the hash map made with Arena\n"
           "ENV Vars:\n"
           "\tNET_IFACE: name of the network interface to attach XDP program\n");
}

int launch_arena(void)
{
    return 0;
}

int launch_baseline(void)
{
    int ret;
    struct baseline *skel = baseline__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    /* Load the some fibbonacci numbers to the bloom filter */
    {
        const int count_fib = 40;
        int a,b,c;
        a = 1;
        b = 1;
        for (int i = 2; i < count_fib; i++) {
            c = a + b;
            a = b;
            b = c;
            my_value_t v = {
                .data[0] = c,
                .data[1] = c + 1,
            };
            ret = bpf_map__update_elem(skel->maps.bloom_filter, 0, 0,
                    &v, sizeof(my_value_t), BPF_ANY);
            assert (ret == 0);
        }
    }

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.baseline_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            baseline__destroy(skel);
            return EXIT_FAILURE;
        }
    }

    /* Keep running and handle signals */
    running = 1;
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    printf("Hit Ctrl+C to terminate ...\n");

    while (running) { pause(); }

    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    baseline__destroy(skel);
    printf("Done!\n");
    return 0;
}

int main(int argc, char *argv[])
{
    usage();
    /*  The program relies on NET_IFACE env variable */
    ifacename = getenv("NET_IFACE");
    if (ifacename == NULL) {
        ifacename = "veth1";
    }
    ifindex = if_nametoindex(ifacename);
    /* TODO: make sure it is running in zero copy mode */
    xdp_flags = 0;
    selected_prog = BASELINE;

    if (argc > 1) {
        if (strncmp(argv[1], "--arena", 7) == 0) {
            selected_prog = ARENA;
        }
    }

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return EXIT_FAILURE;
    }

    switch (selected_prog) {
        case BASELINE:
            return launch_baseline();
            break;
        case ARENA:
            return launch_arena();
            break;
    }
}
