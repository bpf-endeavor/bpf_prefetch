#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "common.h"
#include "prefetching.h"
#include "report_throughput.h"
#include "http_parser.h"
#include "routing.h"

#define HEADER_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define SERVER_PORT 8080

#ifdef SK_SKB
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key,   __u32);
	__type(value, __u64);
	__uint(max_entries, MAX_CONN);
} sock_map SEC(".maps");
#endif

/* Booking data related to parsing HTTP request are kept in this map */
struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key,   __u32);
	__type(value, struct parsing_ctx);
	__uint(max_entries, 1);
} parsing_ctx_map SEC(".maps");

typedef struct {
	__u8 err;
	__u16 i;
	CONTEXT *ctx;
	struct parsing_ctx *pctx;
	__u8 found;
} header_loop_ctx_t;

static long _parse_headers_loop(int ii, void *_ctx)
{
	header_loop_ctx_t *c = _ctx;
	enum HEADER_OPT opt = OPT_NONE;
	int ret;
	/* I need to parse HTTP headers because host header could
	 * change which server config is selected */
	ret = parse_http_header_line(c->ctx, c->pctx, &opt);
	if (ret == INVALID) {
		c->err = 1;
		return 1;
	}
	if (c->pctx->all_header_parsed) {
		c->found = 1;
		return 1;
	}
	if (opt == OPT_HOST) {
		/* We only care about host option for now */
		/* goto header_parsed; */
		c->found = 1;
		return 1;
	}

	return 0; // continue;
}

int prog_parse_header_opt(CONTEXT *skb)
{
	struct parsing_ctx *pctx;
	const int zero = 0;

	pctx = bpf_map_lookup_elem(&parsing_ctx_map, &zero);
	if (pctx == NULL) {
		/* this never happens */
		return ABORTED;
	}

	header_loop_ctx_t c = {
		.err = 0,
		.i = 0,
		.ctx = skb,
		.pctx = pctx,
		.found = 0,
	};
	bpf_loop(MAX_HEADER_OPT_LINES, _parse_headers_loop, &c, 0);
	if (c.err) {
		bpf_printk("Header line is invalid (line: %d)", -1);
		return PASS;
	} else if (c.found) {
		goto header_parsed;
	}
	/* There are more headers that we have not looked at! */
	bpf_printk("some of the headers not parsed!");
	return ABORTED;

header_parsed:
	if (pctx->host_start_off == 0 || pctx->host_end_off == 0) {
		/* HTTP 1.1 and no host is not acceptable */
		bpf_printk("host not found!");
		return ABORTED;
	}

	/* void *data = GET_DATA(skb); */
	/* bpf_printk("host: %s", data+ pctx->host_start_off); */

	/* report_tput(); */
	/* void * data = GET_DATA(skb); */
	/* P(data + 4096); */
	/* return DROP; */
	return prog_route(skb, pctx->host_start_off, pctx->host_end_off);
}

int prog_parse_uri(CONTEXT *ctx)
{
	struct parsing_ctx *pctx;
	const int zero = 0;
	pctx = bpf_map_lookup_elem(&parsing_ctx_map, &zero);
	if (!pctx) {
		/* this never happens */
		return ABORTED;
	}
	int ret = parse_http_uri(ctx, pctx);
	switch (ret) {
		case UNSUPPORTED:
			/* The url is not supported (e.g., the schema is not http://) */
			bpf_printk("URI is not supported!");
			return ABORTED;
		case INVALID:
			bpf_printk("URI is invalide!");
			return ABORTED;
	}
	return prog_parse_header_opt(ctx);
}

#ifdef XDP
sinline int is_relevant(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return 0;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;
	if (ip->protocol != IPPROTO_UDP)
		return 0;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return 0;
	return 1;
}
#endif

#ifdef XDP
SEC("xdp")
#else
SEC("sk_skb/stream_verdict")
#endif
int prog(CONTEXT *ctx)
{
	int ret;
	struct parsing_ctx *pctx;
	const int zero = 0;
	int start_off = 0;

#ifdef XDP
	/* The http message starts at an offset from data */
	start_off = HEADER_SIZE;
	void *data_end = (void *)(__u64)(ctx->data_end);
	if (!is_relevant(data, data_end)) {
		/* ignore packets that are not for our test */
		return PASS;
	}
#endif
	/* bpf_printk("%p", data); */
	/* report_tput(); */
	/* return DROP; */

	/* char *p = data + HEADER_SIZE; */
	/* bpf_printk("-- %s", p); */

	pctx = bpf_map_lookup_elem(&parsing_ctx_map, &zero);
	if (!pctx) {
		/* ths never happens */
		return ABORTED;
	}
	P(&pctx->method_start_off);

#ifdef SK_SKB
	if (bpf_skb_pull_data(ctx, ctx->len) != 0) {
		return PASS;
	}
#endif
	
	void *data = (void *)(__u64)(ctx->data);
	P(data);

	ret = parse_http_request_line(ctx, start_off, pctx);
	switch (ret) {
		case UNSUPPORTED:
			// We do not support this request in eBPF send it to the
			// userspace application.
			bpf_printk("we do not support this request");
			return ABORTED;
		case INVALID:
			bpf_printk("Invalid request line");
			return ABORTED;
	}
	return prog_parse_uri(ctx);
}

char _license[] SEC("license") = "GPL";
