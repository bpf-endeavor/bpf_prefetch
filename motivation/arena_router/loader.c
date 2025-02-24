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
#include "include/arena_lpm_trie.h"
#include "baseline.skel.h"
#include "arena_router.skel.h"

typedef enum {
    BASELINE,
    ARENA
} prog_t;

/* Some global vars */
static char *ifacename;
static int ifindex;
static int xdp_flags;
static prog_t selected_prog;
static volatile int running = 0;
const static int number_of_items = MAX_ENTRIES;

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

/* 
 * @out, a pointer to another pointer, it will be set to the memory allocated
 * for the rules.
 * @returns number of the rules
 * */
int load_routing_dataset(my_key_t **out)
{
    // TODO: this is hardcoded and might brake if the user invoke the program
    // from somewhere else
    const char * file_path = "./dataset/ipv4.txt";
    FILE *f = fopen(file_path, "r");
    char buf[256];
    size_t sz = 0;
    size_t num_entries = 0;
    while ((sz = fread(&buf, 1, 1, f)) != 0) {
        for (size_t i = 0; i < sz; i++) {
            if (buf[i] == '\n')
                num_entries++;
        }
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "failed to seek to the begining of the file\n");
        return -1;
    }

    size_t key_o = 0;
    char ipv4[16]; size_t ipv4_o = 0;
    char pref[8]; size_t pref_o = 0;
    enum {
        READING_IP,
        READING_PREFIX,
    }state = 0;
    my_key_t *keys = calloc(num_entries, sizeof(my_key_t));
    assert(keys != NULL);
    while ((sz = fread(&buf, 1, 1, f)) > 0) {
        for (size_t i = 0; i < sz; i++) {
            char c = buf[i];
            if (c == '\0')
                break;
            switch (state) {
                case READING_IP:
                    if ((c >= '0' && c <= '9') || (c == '.')) {
                        ipv4[ipv4_o++] = c;
                        assert(ipv4_o < 16);
                    } else if (c == '/') {
                        state = READING_PREFIX;
                        ipv4[ipv4_o++] = '\0';
                        assert(ipv4_o < 16);
                        /* printf("ip: %s\n", ipv4); */
                    } else {
                        printf("READING_IP && saw: %c key-index: %lu\n", c, key_o);
                        assert (0);
                    }
                    break;
                case READING_PREFIX:
                    if (c >= '0' && c <= '9') {
                        pref[pref_o++] = c;
                    } else if (c == '\n') {
                        state = READING_IP;
                        pref[pref_o++] = '\0';
                        // we should have key now
                        my_key_t *k = &keys[key_o++];
                        k->prefixlen = atoi(pref);
                        inet_pton(AF_INET, ipv4, &k->data);

                        pref_o = 0;
                        ipv4_o = 0;
                    } else {
                        assert (0);
                    }
                    break;
                default:
                    assert (0);
                    break;
            }
        }
    }

    *out = keys;
    return num_entries;
}

int launch_arena(void)
{
    int ret;
    struct arena_router *skel = arena_router__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    size_t area_sz = 0;
    void *area = NULL;
    arena_lpm_trie_t *lpm = NULL;

    /* Get the begining of the mmapped address */
    area = bpf_map__initial_value(skel->maps.arena, &area_sz);

    printf("key size is: %ld  value size is: %ld  area_sz: %ld\n",
            sizeof(my_key_t), sizeof(my_value_t), area_sz);

    arena_lpm_alloc_args_t arg = {
        .area = area,
        .key_size = sizeof(my_key_t),
        .value_size = sizeof(my_value_t),
        .max_entries = (1 << 21),
        .trie_ptr = &lpm,
    };
    if (userspace_arena_trie_alloc(&arg) != 0) {
        return -1;
    }

    printf("Updating the routing table. Please wait...\n");
    my_key_t *keys = NULL;
    const int number_of_items = load_routing_dataset(&keys);
    for (int i = 0; i < number_of_items; i++) {
        my_key_t *k = &keys[i];
        /* printf("%x/%d\n", k->data, k->prefixlen); */
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        ret = userspace_arena_trie_update_elem(lpm, k, &v, 0);
        if (ret != 0) {
            fprintf(stderr, "Failed to update hash map (%d)\n", ret);
            assert(0);
        }
        if(i % 1024 == 0) {
            printf("                                           \r");
            printf("%d/%d", i, number_of_items);
            printf("\r");
            fflush(stdout);
        }
    }

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.arena_router_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            arena_router__destroy(skel);
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
    arena_router__destroy(skel);
    printf("Done!\n");
    
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

    /* load entries into map */
    printf("Updating the routing table. Please wait...\n");
    my_key_t *keys = NULL;
    const int number_of_items = load_routing_dataset(&keys);
    for (int i = 0; i < number_of_items; i++) {
        my_key_t *k = &keys[i];
        /* printf("%x/%d\n", k->data, k->prefixlen); */
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        ret = bpf_map__update_elem(skel->maps.ipv4_lpm_map, k, sizeof(k), &v,
                sizeof(v), 0);
        if (ret != 0) {
            fprintf(stderr, "Failed to update hash map (%d)\n", ret);
            assert(0);
        }
        if(i % 1024 == 0) {
            printf("                                           \r");
            printf("%d/%d", i, number_of_items);
            printf("\r");
            fflush(stdout);
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
    printf("Ready!\n");
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
