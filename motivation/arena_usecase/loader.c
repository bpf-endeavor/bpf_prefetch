// vim: et sw=4 ts=4:
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>

#include <linux/if_link.h> // XDP_FLAGS_*

#include "include/compiler.h"
#include <bpf/bpf.h>

#include "include/shared_struct.h"
#include "include/bpf_arena_htab.h"
#include "macchiato.skel.h"
#include "cappuccino.skel.h"

/* Some global vars */
static char *ifacename;
static int ifindex;
static int xdp_flags;
static bool use_arena;
static volatile int running = 0;
static struct macchiato *xskel = NULL;
static struct cappuccino *cskel = NULL;
const static int number_of_items = 2000000;

static void handle_signal(int s)
{
    running = 0;
}

static void usage(void)
{
    printf("Usage: prog OPTIONS\n"
           "OPTIONS:\n"
           "\t--arena: use the hash map made with Arena"
           "ENV Vars:\n"
           "\tNET_IFACE: name of the network interface to attach XDP program\n");
}

static void prepare_arena_htab_for_xdp(void)
{
    if (xskel == NULL) {
        /* This must never happen */
        return;
    }

    size_t area_sz = 0;
    void *area = NULL;
    htab_t *htab = NULL;

    /* Get the begining of the mmapped address */
    area = bpf_map__initial_value(xskel->maps.arena, &area_sz);

    printf("key size is: %ld  value size is: %ld\n", sizeof(my_key_t),
            sizeof(my_value_t));

    /* Initialize the htab data-structure */
    htab_init_userspace(area, 8000000 /*max entries*/, &htab);
    /* printf("Number of buckets: %d\n", htab->n_buckets); */

    for (int i = 0; i < number_of_items; i++) {
        my_key_t k = {
            .dport = i,
        };
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        if(htab_update_elem_userspace(htab, &k, &v) != 0) {
            fprintf(stderr, "Failed to insert a value into the hash map\n");
            break;
        }
    }

    /* Expose the htab to the XDP program */
    xskel->bss->rules = htab;

    /* Done initilizing the hash map */
    return;
}

int launch_macchiato(void)
{
    xskel = macchiato__open();
    if (!xskel) {
        fprintf(stderr, "Failed to open macchiato skeleton\n");
        return EXIT_FAILURE;
    }

    if (macchiato__load(xskel)) {
        fprintf(stderr, "Failed to load Macchiato program\n");
        macchiato__destroy(xskel);
        return EXIT_FAILURE;
    }

    /* The XDP program is loaded but is not receiving packets right now */
    prepare_arena_htab_for_xdp();

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(xskel->progs.macchiato_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            macchiato__destroy(xskel);
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
    macchiato__destroy(xskel);
    printf("Done!\n");
    return 0;
}

int launch_cappuccino(void)
{
    int ret;
    cskel = cappuccino__open();
    if (!cskel) {
        fprintf(stderr, "Failed to open cappuccino skeleton\n");
        return EXIT_FAILURE;
    }

    if (cappuccino__load(cskel)) {
        fprintf(stderr, "Failed to load cappuccino program\n");
        cappuccino__destroy(cskel);
        return EXIT_FAILURE;
    }

    /* load entries into map */
    for (int i = 0; i < number_of_items; i++) {
        my_key_t k = {
            .dport = i,
        };
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        ret = bpf_map__update_elem(cskel->maps.rules, &k, sizeof(k), &v,
                sizeof(v), 0);
        if (ret != 0) {
            fprintf(stderr, "Failed to update hash map (%d)\n", ret);
        }
    }

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(cskel->progs.cappuccino_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            cappuccino__destroy(cskel);
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
    cappuccino__destroy(cskel);
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
    use_arena = false;

    if (argc > 1) {
        if (strncmp(argv[1], "--arena", 7) == 0) {
            use_arena = true;
        }
    }

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return EXIT_FAILURE;
    }

    if (use_arena) {
        return launch_macchiato();
    } else {
        return launch_cappuccino();
    }
}
