#ifndef BPF_LOADER_HELPERS_H
#define BPF_LOADER_HELPERS_H
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h> // XDP_FLAGS_*
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "runner_args.h"
#include "runner_global_context.h"
#include "csum.h"
#include "mac_addr.h"
#define MAX_BUF 4096

#ifndef BPF_F_TEST_XDP_LIVE_FRAMES
#define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
#endif

static int xdp_flags = (XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE);

void detach_xdp_program(void)
{
	bpf_xdp_detach(args.ifindex, xdp_flags, NULL);
}

void attach_xdp_program(void)
{
	int ret;
	ret = bpf_xdp_attach(args.ifindex, context.prog_fd, xdp_flags, NULL);
	if (ret) {
		perror("failed to attach xdp program\n");
		detach_xdp_program();
		exit(EXIT_FAILURE);
	}
}

int load_bpf_binary_and_get_program(void)
{
	int ret;
	struct bpf_object *bpfobj;
	struct bpf_program *prog;
	int prog_fd;
	bpfobj = bpf_object__open_file(args.binary_path, NULL);
	if (!bpfobj) {
		fprintf(stderr, "Failed to open the BPF binary!\n    %s\n",
				args.binary_path);
		exit(EXIT_FAILURE);
	}
	/* Load the program to the kernel */
	ret = bpf_object__load(bpfobj);
	if (ret != 0) {
		fprintf(stderr, "Failed to load program to the kernel\n");
		exit(EXIT_FAILURE);
	}
	/* Get program fd */
	prog = bpf_object__find_program_by_name(bpfobj, args.progname);
	if (prog == NULL) {
		fprintf(stderr, "Failed to find xdp_prog\n");
		exit(EXIT_FAILURE);
	}
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 1) {
		fprintf(stderr, "Failed to find the program file descriptor\n");
		exit(EXIT_FAILURE);
	}
	/* Update the global state */
	context.bpfobj = bpfobj;
	context.prog = prog;
	context.prog_fd = prog_fd;
	return prog_fd;
}

/*
 * input: the input packet to send
 * output: a buffer to receive the result (output packet)
 * */
int send_packet(int prog_fd, const char *input, size_t in_size,
		char *output, size_t out_size)
{
	/* time_t before, after; */
	int ret;
	struct bpf_test_run_opts test_opts;
	struct xdp_md ctx_in;
	/* struct xdp_md ctx_out; */
	/* Invoke BPF program */
	memset(&ctx_in, 0, sizeof(ctx_in));
	memset(&test_opts, 0, sizeof(struct bpf_test_run_opts));
	ctx_in.data_end = in_size;
	test_opts.sz = sizeof(struct bpf_test_run_opts);
	test_opts.data_in = input;
	test_opts.data_size_in = in_size;
	test_opts.ctx_in = &ctx_in;
	test_opts.ctx_size_in = sizeof(ctx_in);
	test_opts.repeat = args.repeat;
	if (context.live == 1) {
		/* printf("trying live flag...\n"); */
		test_opts.flags = BPF_F_TEST_XDP_LIVE_FRAMES;
#ifdef KERENL_v5_18
		test_opts.batch_size = 0;
#endif
		/* test_opts.batch_size = 1; */
		ctx_in.ingress_ifindex = args.ifindex;
		/* printf("ifindex is %d\n", args.ifindex); */
		assert(args.ifindex > 0);
	} else {
		test_opts.flags = 0;
#ifdef KERENL_v5_18
		test_opts.batch_size = 0;
#endif
		test_opts.data_out = output;
		test_opts.data_size_out = out_size;
		/* test_opts.ctx_out = &ctx_out; */
		/* test_opts.ctx_size_out = sizeof(ctx_out); */
	}
	test_opts.cpu = 0;
	/* before = read_tsc(); */
	ret = bpf_prog_test_run_opts(prog_fd, &test_opts);
	/* after = read_tsc(); */
	if (ret < 0) {
		perror("something went wrong\n");
		return -1;
	}
	/* context.last_test_duration = (after - before) / (double)args.repeat; */
	context.last_test_duration = test_opts.duration;
	return test_opts.retval;
}

int _send_payload(int prog_fd, const char *input, char *output, size_t out_size, size_t N)
{
	int ret;
	uint64_t csum;
	/* Prepare the packet */
	const size_t payload_size = strlen(input);
	char *pkt = calloc(1, MAX_BUF);
	size_t pkt_size = sizeof(struct ethhdr) + sizeof(struct iphdr)
		+ sizeof(struct udphdr) + payload_size;
	struct ethhdr *eth = (struct ethhdr *)pkt;
	struct iphdr *ip   = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	char *payload = (char *)(udp + 1);
	memset(eth->h_source, 0x00, ETH_ALEN);
	get_mac_addr(args.ifindex, eth->h_dest);
	/* memset(eth->h_dest, 0x00, ETH_ALEN); */
	/* char my_mac_addr[6] = {0x4c,0xcc,0x6a,0xdb,0xbd,0xf8}; */
	/* memcpy(eth->h_source, my_mac_addr, 6); */
	/* memcpy(eth->h_dest, my_mac_addr, 6); */
	eth->h_proto = htons(ETH_P_IP);
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr)
			+ payload_size);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	inet_pton(AF_INET, args.sender_ip, &ip->saddr);
	inet_pton(AF_INET, args.receiver_ip, &ip->daddr);
	/* ip->saddr = htonl(0x7F000001); */
	/* ip->daddr = htonl(0x7F000001); */
	ip->check = 0;
	csum = 0;
	ipv4_csum_inline(ip, &csum);
	ip->check = htons(csum);

	udp->source = htons(56124);
	udp->dest = htons(8080);
	udp->len = htons(sizeof(struct udphdr) + payload_size);
	/* it is fine to not have udp checksum */
	udp->check = 0;
	memcpy(payload, input, payload_size);
	csum = 0;
	void *data_end = payload + payload_size;
	ipv4_l4_csum_inline(data_end, udp, ip, &csum);
	udp->check = ntohs(csum);
	for (size_t i = 0; i < N; i++)
		ret = send_packet(prog_fd, pkt, pkt_size, output, out_size);
	free(pkt);
	return ret;
}

int send_payload(int prog_fd, const char *input, char *output, size_t out_size)
{
	return _send_payload(prog_fd, input, output, out_size, 1);
}
#endif
