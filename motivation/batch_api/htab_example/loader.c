// vim: et sw=4 ts=4:
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>

#include <linux/if_link.h> // XDP_FLAGS_*
#include <bpf/bpf.h>
#include "arena-ds/htab.h"
#include "exp.skel.h"

#define HTAB_MAX_ENTRIES 8000000

typedef enum {
    PROG_NORMAL,
    PROG_BATCH,
} prog_t;

/* Some global vars */
static char *ifacename;
static int ifindex;
static int xdp_flags;
static prog_t selected_prog;
static volatile int running = 0;
const static int number_of_items = 2000000;

static void handle_signal(int s)
{
    running = 0;
}

static void usage(void)
{
    printf("Usage: prog OPTIONS\n"
           "OPTIONS:\n"
           "\t--normal: \n"
           "\t--batch: \n"
           "ENV Vars:\n"
           "\tNET_IFACE: name of the network interface to attach XDP program\n");
}

static void prepare_arena_htab_for_xdp(void *arena, void **mem_ptr)
{
    size_t area_sz = 0;
    void *area = NULL;
    htab_t *htab = NULL;

    /* Get the begining of the mmapped address */
    area = bpf_map__initial_value(arena, &area_sz);

    printf("key size is: %ld  value size is: %ld\n", sizeof(my_key_t),
            sizeof(my_value_t));

    /* Initialize the htab data-structure */
    htab_init_userspace(area, HTAB_MAX_ENTRIES /*max entries*/, &htab);
    /* printf("Number of buckets: %d\n", htab->n_buckets); */

    my_key_t k;
    for (int i = 0; i < number_of_items; i++) {
        *(int *)&k.data = i;
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.data, "hello %d\n", i);
        if(htab_update_elem_userspace(htab, &k, &v) != 0) {
            fprintf(stderr, "Failed to insert a value into the hash map\n");
            break;
        }
    }

    /* Expose the htab to the XDP program */
    *mem_ptr = htab;

    /* Done initilizing the hash map */
    return;
}

int parse_args(int argc, char *argv[])
{
    /*  The program relies on NET_IFACE env variable */
    ifacename = getenv("NET_IFACE");
    if (ifacename == NULL) {
        ifacename = "veth1";
    }
    ifindex = if_nametoindex(ifacename);
    /* TODO: make sure it is running in zero copy mode */
    xdp_flags = 0;
    selected_prog = PROG_NORMAL;

    if (argc > 1) {
        if (strncmp(argv[1], "-h", 2) == 0 ||
                strncmp(argv[1], "--help", 6) == 0) {
            return 1;
        } else if (strncmp(argv[1], "--normal", 7) == 0) {
            selected_prog = PROG_NORMAL;
        } else if (strncmp(argv[1], "--batch", 7) == 0) {
            selected_prog = PROG_BATCH;
        }
    }

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (parse_args(argc, argv) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    struct exp *skel = NULL;
    skel = exp__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return EXIT_FAILURE;
    }

    if (exp__load(skel)) {
        fprintf(stderr, "Failed to load program\n");
        exp__destroy(skel);
        return EXIT_FAILURE;
    }

    /* The XDP program is loaded but is not receiving packets right now */
    prepare_arena_htab_for_xdp(skel->maps.arena, (void **)&skel->bss->map);

    struct bpf_program *main_prog = NULL;
    switch(selected_prog) {
        case PROG_NORMAL:
            main_prog = skel->progs.key_val_main;
            break;
        case PROG_BATCH:
            main_prog = skel->progs.bbb_key_val_main;
            break;
        default:
            fprintf(stderr, "Unexpected program mode\n");
            return EXIT_FAILURE;
    }

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(main_prog);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            exp__destroy(skel);
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
    exp__destroy(skel);
    printf("Done!\n");
    return 0;
}
