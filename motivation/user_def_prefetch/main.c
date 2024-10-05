#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/in.h>
#include <linux/if_link.h> // XDP_FLAGS_*
#include <net/if.h> /* if_nametoindex */
#include <signal.h>

#include "build/bpf/bench.bpf.h"

#ifndef IFNAME
#pragma GCC error "IFNAME is not defined"
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

static int running = 0;
void handle_sig(int s)
{
	running = 1;
	return;
}

int main(int argc, char **argv)
{
	int ret;
	struct bench_bpf *skel = NULL;
	const int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	const char *ifname = IFNAME;
	printf("XDP interface: %s\n", ifname);
	int ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		printf("Interface not found!\n");
		return 1;
	}
	struct attach_request bpf_req = {
		.prog_name = "prog",
		.bpf_hook = XDP,
		.ifindex = ifindex,
	};
	skel = bench_bpf__open_and_load();
	ret = load_xdp(skel->obj, &bpf_req, xdp_flags);
	if (ret != 0) {
		goto clean_up;
	}

	signal(SIGINT, handle_sig);
	signal(SIGHUP, handle_sig);
	running = 1;

	printf("Hit Ctrl-C ...\n");
	pause();
	printf("Done!\n");
clean_up:
	detach_xdp(&bpf_req, xdp_flags);
	bench_bpf__destroy(skel);
	return 0;
}
