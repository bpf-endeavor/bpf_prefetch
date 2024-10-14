#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "../include/bpf/http_parser.h"
#define HEADER_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))

/* Define the unofficial helper function */
static long (*bpf_prefetch)(void *ptr__ign) = (void *) 212;
#ifdef PREFETCH
#define P(x) bpf_prefetch(x)
#else
#define P(x)
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
	struct xdp_md *ctx;
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
		/* DUMP("All headers has been parsed (off:%d)", pctx->head_off); */
		/* goto header_parsed; */
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

int prog_parse_header_opt(struct xdp_md *skb)
{
	/* DUMP("Web server parse header"); */
	int ret;
	struct parsing_ctx *pctx;
	const int zero = 0;

	pctx = bpf_map_lookup_elem(&parsing_ctx_map, &zero);
	if (pctx == NULL) {
		return XDP_PASS;
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
		DUMP("Header line is invalid (line: %d)", -1);
		/* return reply_with_error(skb, 405); */
		return XDP_PASS;
	} else if (c.found) {
		goto header_parsed;
	}
	/* There are more headers that we have not looked at! */
	return XDP_PASS;

header_parsed:
	if (pctx->host_start_off == 0 || pctx->host_end_off == 0) {
		/* HTTP 1.1 and no host is not acceptable */
		/* return reply_with_error(skb, 405); */
		return XDP_PASS;
	}

	/* void *data = GET_DATA(skb); */
	/* DUMP("host: %s", data+ pctx->host_start_off); */

	return XDP_DROP;
}

int prog_parse_uri(struct xdp_md *ctx)
{
	struct parsing_ctx *pctx;
	const int zero = 0;
	pctx = bpf_map_lookup_elem(&parsing_ctx_map, &zero);
	if (!pctx) {
		return XDP_PASS;
	}
	int ret = parse_http_uri(ctx, pctx);
	switch (ret) {
		case UNSUPPORTED:
			/* The url is not supported (e.g., the schema is not http://) */
			DUMP("URI is not supported!");
			return SK_PASS;
		case INVALID:
			DUMP("URI is invalide!");
			/* return reply_with_error(skb, 405); */
			return XDP_PASS;
	}

	return prog_parse_header_opt(ctx);
}

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	/* DUMP("Web server main"); */
	int ret;
	struct parsing_ctx *pctx;
	const int zero = 0;

	/* void *data = (char *)(__u64)(ctx->data); */
	/* char *p = data + HEADER_SIZE; */
	/* DUMP("-- %s", p); */

	pctx = bpf_map_lookup_elem(&parsing_ctx_map, &zero);
	if (!pctx) {
		return XDP_PASS;
	}

	ret = parse_http_request_line(ctx, HEADER_SIZE, pctx);
	switch (ret) {
		case UNSUPPORTED:
			// We do not support this request in eBPF send it to the
			// userspace application.
			return XDP_PASS;
		case INVALID:
			DUMP("Invalid request line");
			/* return reply_with_error(skb, 405); */
			return XDP_PASS;
	}

	return prog_parse_uri(ctx);
}

char _license[] SEC("license") = "GPL";
