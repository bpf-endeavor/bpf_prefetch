/*
 * This is a control plane for the changes I make to the katran.
 * It is intended to complement the original katran server program.
 *
 * */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "shared_map.h"

typedef struct {
	uint32_t next;
	uint32_t hash;
	uint32_t ptr;
	uint32_t freelist_next;
	char key[0];
} node_t;

typedef struct {
	uint32_t freelist_next;
	char val[0];
} entry_t;

typedef struct {
	uint32_t first;
} bucket_t;

/* This name is set in balancer.bpf.c */
#define SMAP_NAME "s_map"
#define ATABLE_NAME SMAP_NAME"_atable"
#define BTABLE_NAME SMAP_NAME"_btable"
#define NTABLE_NAME SMAP_NAME"_ntable"

int main(int argc, char *argv[])
{
	int ret;
	uint32_t max_entries;
	entry_t *tmp_e;
	node_t *tmp_n;
	struct find_map_res map_res = {};
	printf("Expect the Katran to be running\n");

	// prepare the entries freelist
	ret = get_shared_map(BTABLE_NAME, &map_res);
	if (ret != 0) {
		fprintf(stderr, "Failed to find the map %s\n", BTABLE_NAME);
		return 1;
	}
	tmp_e = calloc(1, map_res.info.value_size);
	if (tmp_e == NULL) {
		fprintf(stderr, "failed to allocate memory");
		return 1;
	}
	max_entries = map_res.info.max_entries;
	printf("Found %s with %d entries\n", BTABLE_NAME, max_entries);
	for (int i = 0; i < max_entries; i++) {
		tmp_e->freelist_next = (i+1)  % max_entries;
		bpf_map_update_elem(map_res.fd, &i, tmp_e, BPF_ANY);
	}

	// prepare the nodes freelist
	ret = get_shared_map(NTABLE_NAME, &map_res);
	if (ret != 0) {
		fprintf(stderr, "Failed to find the map %s\n", NTABLE_NAME);
		return 1;
	}
	tmp_n = calloc(1, map_res.info.value_size);
	if (tmp_n == NULL) {
		fprintf(stderr, "failed to allocate memory");
		return 1;
	}
	max_entries = map_res.info.max_entries;
	printf("Found %s with %d entries\n", NTABLE_NAME, max_entries);
	for (int i = 0; i < max_entries; i++) {
		tmp_n->freelist_next = (i+1) % max_entries;
		bpf_map_update_elem(map_res.fd, &i, tmp_n, BPF_ANY);
	}

	printf("configuring done!\n");
	return 0;
}
