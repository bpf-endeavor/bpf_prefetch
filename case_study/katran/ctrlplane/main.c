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
	char key[0];
} node_t;

typedef struct {
	uint32_t freelist_next;
	char val[0];
} entry_t;

typedef struct {
	node_t first;
} bucket_t;

/* This name is set in balancer.bpf.c */
#define SMAP_NAME "s_map"
#define ATABLE_NAME SMAP_NAME"_atable"
#define BTABLE_NAME SMAP_NAME"_btable"
#define NTABLE_NAME SMAP_NAME"_ntable"

int main(int argc, char *argv[])
{
	int ret;
	struct find_map_res map_res = {};
	printf("Expect the Katran to be running\n");
	ret = get_shared_map(NTABLE_NAME, &map_res);
	if (ret != 0) {
		fprintf(stderr, "Failed to find the map %s\n", NTABLE_NAME);
		return 1;
	}
	printf("Found %s with %d entries\n", NTABLE_NAME, map_res.info.max_entries);
	// prepare the freelist
	for (int i = 0; i < map_res.info.max_entries; i++) {
		bpf_map_update_elem();
	}
	return 0;
}
