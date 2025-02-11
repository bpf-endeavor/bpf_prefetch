#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>

#include "include/compiler.h"
#include <bpf/bpf.h>

#include "include/shared_struct.h"

#include "include/bpf_arena_htab.h"

#include "macchiato.skel.h"

/* Some global vars */
static volatile int running = 0;
static struct macchiato *xskel = NULL;

static void handle_signal(int s) {
    running = 0;
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
    htab_init_userspace(area, &htab);

    const __u16 base_port = 8000;
    for (int i = 0; i < 1; i++) {
        /* printf("i = %d\n", i); */
        __u16 tmp_port = htons(base_port + i);
        my_key_t tmp_key;
        memset(&tmp_key, 0, sizeof(tmp_key));
        tmp_key.dport = tmp_port;
        my_value_t tmp_val;
        memset(&tmp_val, 0, sizeof(tmp_val));
        sprintf(tmp_val.msg, "hello %d\0", i);
        /* printf("%s\n", tmp_val.msg); */
        if(htab_update_elem_userspace(htab, &tmp_key, &tmp_val) != 0) {
            fprintf(stderr, "Failed to insert a value into the hash map\n");
            break;
        }
    }

    /* Expose the htab to the XDP program */
    xskel->bss->rules = htab;

    /* Done initilizing the hash map */
    return;
}

int main(int argc, char *argv[])
{
    char *ifacename = "veth1";
    const int ifindex = if_nametoindex(ifacename);
    const int xdp_flags = 0;

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return EXIT_FAILURE;
    }

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

    sleep(1);
    /* The XDP program is loaded but is not receiving packets right now */
    prepare_arena_htab_for_xdp();

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(xskel->progs.macchiato_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
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
