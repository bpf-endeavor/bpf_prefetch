#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/in.h>
#include <linux/if_link.h> // XDP_FLAGS_*
#include <net/if.h> /* if_nametoindex */
#include <signal.h>

#include "build/bpf/flow_cls_bench.bpf.h"
#include "struct_def.h"

#ifndef IFNAME
#pragma GCC error "IFNAME is not defined"
/* #define IFNAME  "enp7s0" */
#endif

#define SRC_IP 0xC0A8C865
#define DST_IP 0xC0A8C866
#define MAX_COUNT_FLOWS 100000

enum attach_type {
	SK_SKB,
	XDP,
	TC,
	GXDP,
};

struct attach_request {
	char *prog_name;
	enum attach_type bpf_hook;
	int ifindex;
};

int load_xdp(struct bpf_object *bpfobj, struct attach_request *bpf_req,
		uint32_t xdp_flags)
{
	/* Attach XDP program */
	struct bpf_program *prog = bpf_object__find_program_by_name(bpfobj,
			bpf_req->prog_name);
	if (!prog) {
		printf("Failed to find xdp program (%s)\n", bpf_req->prog_name);
		return 1;
	}

	int prog_fd = bpf_program__fd(prog);
	if (bpf_xdp_attach(bpf_req->ifindex, prog_fd, xdp_flags, NULL) != 0) {
		printf("if: %d prog fd: %d\n", bpf_req->ifindex, prog_fd);
		printf("Failed to attach XDP program! %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

void detach_xdp(struct attach_request *bpf_req, uint32_t xdp_flags)
{
	bpf_xdp_detach(bpf_req->ifindex, xdp_flags, NULL);
}

int fill_policy_map(struct bpf_map *map)
{
	int ret;
	flow_key_t key;
	FILE *f;

	f = fopen("flows.txt", "r");
	if (f == NULL) {
		printf("Failed to open file\n");
		return 1;
	}

	memset(&key, 0, sizeof(key));
	/* Fill the map with some rules */
	flow_state_t state = {
		.mapped_ip = 0xafafafaf,
		.counter = 0,
		.verdict = XDP_DROP,
	};

	for (int i = 0; i < MAX_COUNT_FLOWS; i++) {
		short c = 0, d = 0;
		ret = fscanf(f, "%hu %hu\n", &c, &d);
		if (ret != 2) {
			printf("Failed to read flow from file (%d)\n", ret);
			fclose(f);
			return 1;
		}
		/* key = (flow_key_t){a, c, b, d, e}; */
		key = (flow_key_t){SRC_IP, c, DST_IP, d, IPPROTO_UDP};
		/* printf("%d %hu\n", key.src_port, d); */
		ret = bpf_map__update_elem(map, &key, sizeof(key), &state, sizeof(state), BPF_NOEXIST);
		if (ret != 0) {
			printf("Failed to insert rule!\n");
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

static int running = 0;
void handle_sig(int s)
{
	running = 1;
	return;
}

void check_key_dist(struct bpf_map *map)
{
	int ret;
	flow_key_t key;
	flow_state_t state;
	FILE *f;

	f = fopen("flows.txt", "r");
	if (f == NULL) {
		printf("Failed to open file\n");
		return;
	}

	memset(&key, 0, sizeof(key));
	memset(&state, 0, sizeof(state));

	for (int i = 0; i < MAX_COUNT_FLOWS; i++) {
		short c = 0, d = 0;
		ret = fscanf(f, "%hu %hu\n", &c, &d);
		if (ret != 2) {
			printf("Failed to read flow from file (%d)\n", ret);
			fclose(f);
			return;
		}
		key = (flow_key_t){SRC_IP, c, DST_IP, d, IPPROTO_UDP};
		ret = bpf_map__lookup_elem(map, &key, sizeof(key), &state, sizeof(state), 0);
		if (ret != 0) {
			printf("Failed to insert rule!\n");
			fclose(f);
			return;
		}
		printf("%llu\n", state.counter);
	}
	fclose(f);
	return;
}

int main(int argc, char **argv)
{
	int ret;
	struct flow_cls_bench_bpf *skel = NULL;
	const int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	const char *ifname = IFNAME;
	printf("XDP interface: %s\n", ifname);
	int ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		printf("Interface not found!\n");
		return 1;
	}
	struct attach_request bpf_req = {
		.prog_name = "xdp_prog",
		.bpf_hook = XDP,
		.ifindex = ifindex,
	};
	skel = flow_cls_bench_bpf__open_and_load();
	ret = load_xdp(skel->obj, &bpf_req, xdp_flags);
	if (ret != 0) {
		goto clean_up;
	}

	ret = fill_policy_map(skel->maps.policy_map);
	if (ret != 0) {
		goto clean_up;
	}

	signal(SIGINT, handle_sig);
	signal(SIGHUP, handle_sig);
	running = 1;

	printf("Hit Ctrl-C ...\n");
	pause();
	printf("Done!\n");
	/* check_key_dist(skel->maps.policy_map); */
clean_up:
	detach_xdp(&bpf_req, xdp_flags);
	flow_cls_bench_bpf__destroy(skel);
	return 0;
}
