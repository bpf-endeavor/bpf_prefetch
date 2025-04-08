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
#include <bpf/bpf.h>

// data-structures
#include "include/shared_struct.h"
#include "include/treap.h"
#include "arena-ds/fixed-point/fp.h"

// sekeleton objects
#include "cvm.skel.h"
#include "cvm_prefetch.skel.h"

typedef enum {
    BASELINE,
    WITH_PREFETCHING,
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
           "\t--prefetch: use the version with software prefetching\n"
           "ENV Vars:\n"
           "\tNET_IFACE: name of the network interface to attach XDP program\n");
}

static int launch_baseline(void)
{
    int ret;
    struct cvm *skel = cvm__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    size_t area_sz = 0;
    void *area = NULL;
    arena_treap_t *treap = NULL;
    uint32_t num_pages = 0;

    /* Get the begining of the mmapped address */
    area = bpf_map__initial_value(skel->maps.arena, &area_sz);
    printf("key size is: %ld\n", sizeof(my_key_t));

    arena_treap_alloc_t arg = {
        .area = area,
        .area_size = 0, // TODO: get the max size of area and pass it here
        .key_size = sizeof(my_key_t),
        .max_entries = TREAP_MAX_SIZE,
        .max_height = TREAP_MAX_HEIGHT,
        .treap_out = &treap,
        .allocated_pages = &num_pages,
    };
    if (userspace_arena_treap_alloc(&arg) != 0) {
        return -1;
    }

    skel->bss->treap = treap;
    skel->bss->p = (1 << 31); // FP_ONE
    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.cvm_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            cvm__destroy(skel);
            return EXIT_FAILURE;
        }
    }

    /* Keep running and handle signals */
    running = 1;
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    printf("Ready!\n");
    printf("Hit Ctrl+C to terminate ...\n");

    while (running) { pause(); }

    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    cvm__destroy(skel);
    printf("Done!\n");
}

static int launch_with_prefetching(void)
{
    int ret;
    struct cvm_prefetch *skel = cvm_prefetch__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    size_t area_sz = 0;
    void *area = NULL;
    arena_treap_t *treap = NULL;
    uint32_t num_pages = 0;

    /* Get the begining of the mmapped address */
    area = bpf_map__initial_value(skel->maps.arena, &area_sz);
    printf("key size is: %ld\n", sizeof(my_key_t));

    arena_treap_alloc_t arg = {
        .area = area,
        .area_size = 0, // TODO: get the max size of area and pass it here
        .key_size = sizeof(my_key_t),
        .max_entries = TREAP_MAX_SIZE,
        .max_height = TREAP_MAX_HEIGHT,
        .treap_out = &treap,
        .allocated_pages = &num_pages,
    };
    if (userspace_arena_treap_alloc(&arg) != 0) {
        return -1;
    }

    skel->bss->treap = treap;
    skel->bss->p = (1 << 31); // FP_ONE
    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.cvm_prefetch_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            cvm_prefetch__destroy(skel);
            return EXIT_FAILURE;
        }
    }

    /* Keep running and handle signals */
    running = 1;
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    printf("Ready!\n");
    printf("Hit Ctrl+C to terminate ...\n");

    while (running) { pause(); }

    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    cvm_prefetch__destroy(skel);
    printf("Done!\n");
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
        if (strncmp(argv[1], "--prefetch", 10) == 0) {
            selected_prog = WITH_PREFETCHING;
        }
    }

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return EXIT_FAILURE;
    }

    if (selected_prog == BASELINE) {
        return launch_baseline();
    } else {
        return launch_with_prefetching();
    }

    return 0;
}
