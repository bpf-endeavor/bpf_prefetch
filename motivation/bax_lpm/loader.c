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

// sekeleton objects
#include "lpm_test.skel.h"
#include "include/dat.h"
#include "dat_test.skel.h"
#include "dat_enhanced.skel.h"

#define MIN(a, b) ((a) > (b) ? (b) : (a))

typedef enum {
    LPM_TRIE,
    ARENA_DAT,
    ARENA_DAT_BAX
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
           "\t--lpm: use LPM Trie (default option)\n"
           "\t--dat: use the Arena Double Array Trie implementation\n"
           "\t--bax-dat: Beeswax version of Arena Double Array Trie\n"
           "ENV Vars:\n"
           "\tNET_IFACE: name of the network interface to attach XDP program\n");
}

/*
 * @out, a pointer to another pointer, it will be set to the memory allocated
 * for the rules.
 * @returns number of the rules
 * */
static int load_routing_dataset(my_key_t **out)
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
    fclose(f);
    return num_entries;
}

static int launch_baseline(void)
{
    int ret;
    struct lpm_test *skel = lpm_test__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    /* load entries into map */
    printf("Updating the routing table. Please wait...\n");
    my_key_t *keys = NULL;
    int number_of_items = load_routing_dataset(&keys);
    number_of_items = MIN(number_of_items, MAX_ENTRIES);
    for (int i = 0; i < number_of_items; i++) {
        my_key_t *k = &keys[i];
        /* printf("%x/%d\n", k->data, k->prefixlen); */
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        ret = bpf_map__update_elem(skel->maps.ipv4_lpm_map, k, sizeof(k), &v,
                sizeof(v), 0);
        if (ret != 0) {
            fprintf(stderr, "Failed to update LPM TRIE map (%d)\n", ret);
            assert(0);
        }
        if(i % 1024 == 0) {
            printf("                                           \r");
            printf("%d/%d", i, number_of_items);
            printf("\r");
            fflush(stdout);
        }
    }
    printf("\n");

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.lpm_test_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            lpm_test__destroy(skel);
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
    lpm_test__destroy(skel);
    printf("Done!\n");
    return 0;
}

static void __prepare_dat(struct bpf_map *arena, arena_dat_t **_dat)
{
    int err;
    uint32_t allocated_area = 0;
    size_t area_size = 0;
    void *area = NULL;
    area = bpf_map__initial_value(arena, &area_size);
    if (area == NULL) {
        fprintf(stderr, "Failed to initialize Arena\n");
        exit(1);
    }

    *_dat = NULL;
    arena_dat_alloc_t arg = {
        .area = area,
        .area_size = area_size,
        .max_entries = MAX_ENTRIES,
        .max_nodes = 200L * 1000L * 1000L,
        .out = _dat,
        .allocated_area =  &allocated_area,
    };
    err = userspace_arena_dat_alloc(&arg);
    if (err != 0 || *_dat == NULL) {
        fprintf(stderr, "Failed to initialize DAT!\n");
        exit(1);
    }
}

static int launch_arena_dat(void)
{
    int ret;
    struct dat_test *skel = dat_test__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    __prepare_dat(skel->maps.arena, &skel->bss->dat);

    /* load entries into map */
    printf("Updating the routing table. Please wait...\n");
    my_key_t *keys = NULL;
    int number_of_items = load_routing_dataset(&keys);
    number_of_items = MIN(number_of_items, MAX_ENTRIES);
    for (int i = 0; i < number_of_items; i++) {
        my_key_t *k = &keys[i];
        /* printf("%x/%d\n", k->data, k->prefixlen); */
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        /* const uint32_t ipv4_addr = htonl(k->data); */
        const uint8_t *ipv4_addr = (void *)&k->data;
        // printf("%d.%d.%d.%d\n", ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
        ret = dat_insert(skel->bss->dat,
                ipv4_addr, k->prefixlen, (uint8_t *)&v);
        if (ret != 0) {
            fprintf(stderr, "Failed to update Arena DAT (err: %d)\n", ret);
            assert(0);
        }
        if(i % 1024 == 0) {
            printf("                                           \r");
            printf("%d/%d", i, number_of_items);
            printf("\r");
            fflush(stdout);
        }
    }
    printf("\n");

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.dat_test_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            dat_test__destroy(skel);
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
    dat_test__destroy(skel);
    printf("Done!\n");
    return 0;
}

static int launch_arena_dat_bax(void)
{
    int ret;
    struct dat_enhanced *skel = dat_enhanced__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load skeleton\n");
        return EXIT_FAILURE;
    }

    __prepare_dat(skel->maps.arena, &skel->bss->dat);

    /* load entries into map */
    printf("Updating the routing table. Please wait...\n");
    my_key_t *keys = NULL;
    int number_of_items = load_routing_dataset(&keys);
    number_of_items = MIN(number_of_items, MAX_ENTRIES);
    for (int i = 0; i < number_of_items; i++) {
        my_key_t *k = &keys[i];
        /* printf("%x/%d\n", k->data, k->prefixlen); */
        my_value_t v;
        memset(&v, 0, sizeof(v));
        sprintf(v.msg, "hello %d\n", i);
        /* const uint32_t ipv4_addr = htonl(k->data); */
        const uint8_t *ipv4_addr = (void *)&k->data;
        // printf("%d.%d.%d.%d\n", ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
        ret = dat_insert(skel->bss->dat,
                ipv4_addr, k->prefixlen, (uint8_t *)&v);
        if (ret != 0) {
            fprintf(stderr, "Failed to update Arena DAT (err: %d)\n", ret);
            assert(0);
        }
        if(i % 1024 == 0) {
            printf("                                           \r");
            printf("%d/%d", i, number_of_items);
            printf("\r");
            fflush(stdout);
        }
    }
    printf("\n");

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(skel->progs.bbb_dat_test_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            dat_enhanced__destroy(skel);
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
    dat_enhanced__destroy(skel);
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
    selected_prog = LPM_TRIE;

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (strncmp(arg, "--lpm", 5) == 0) {
            selected_prog = LPM_TRIE;
        } else if (strncmp(arg, "--dat", 5) == 0) {
            selected_prog = ARENA_DAT;
        } else if (strncmp(arg, "--bax-dat", 9) == 0) {
            selected_prog = ARENA_DAT_BAX;
        } else if (strncmp(arg, "--help", 6) == 0 ||
                strncmp(arg, "-h", 2) == 0) {
            return 0;
        }
    }

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return EXIT_FAILURE;
    }

    switch (selected_prog) {
        case LPM_TRIE:
            printf("Scenario: baseline BPF_MAP_TYPE_LPM_TRIE\n");
            return launch_baseline();
            break;
        case ARENA_DAT:
            printf("Scenario: baseline ARENA Double Array Trie\n");
            return launch_arena_dat();
            break;
        case ARENA_DAT_BAX:
            printf("Scenario: Beeswax ARENA Double Array Trie\n");
            return launch_arena_dat_bax();
            break;
        default:
            exit(1);
    }
    return 0;
}

