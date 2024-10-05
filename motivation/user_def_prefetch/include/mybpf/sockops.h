#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#include "my_bpf/commons.h"

#define MAX_CONN 65536
#ifndef AF_INET
#define AF_INET 2
#endif

struct connection_state;

#include "sockops_shared.h"

/* Head of connection ring */
struct count_sock {
	__u16 value;
	struct bpf_spin_lock lock;
};

/* Context of a socket */
struct sock_context {
	__u32 sock_map_index;
	struct connection_state state;
};

/* BPF maps ---------------*/
struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, struct conn_monitor_config);
	__uint(max_entries, 1);
} conn_monitor_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key,   __u32);
	__type(value, __u64);
	__uint(max_entries, MAX_CONN);
} sock_map SEC(".maps");

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, struct count_sock);
	__uint(max_entries, 1);
} count_sock_map SEC(".maps");

struct {
	/* __uint(type,  BPF_MAP_TYPE_SK_STORAGE); */
	__uint(type,  BPF_MAP_TYPE_HASH);
	/* __type(key,   __u32); */
	__type(key,   __u64);
	__type(value, struct sock_context);
	__uint(max_entries, MAX_CONN);
	/* __uint(map_flags, BPF_F_NO_PREALLOC); */
} sock_ctx_map SEC(".maps");
/* BPF maps ---------------*/

SEC("sockops")
int monitor_connections(struct bpf_sock_ops *skops)
{
	void *data;
	void *data_end;
	struct tcphdr *tcp;
	int ret;
	struct count_sock *count;
	struct sock_context *ctx;
	int sk_index;
	struct conn_monitor_config *conf;

	data = (void *)(long)skops->skb_data;
	data_end = (void *)(long)skops->skb_data_end;
	ret = 0;
	count = bpf_map_lookup_elem(&count_sock_map, &ret);
	if (!count) {
		/* Should never happen */
		bpf_printk("failed to get count map");
		return 0;
	}

	if (!skops->sk) {
		/* Should never happen */
		return 0;
	}

	/* ctx = bpf_sk_storage_get(&sock_ctx_map, skops->sk, NULL, */
	/* 		BPF_LOCAL_STORAGE_GET_F_CREATE); */

	__u64 cookie = bpf_get_socket_cookie(skops);
	ctx = bpf_map_lookup_elem(&sock_ctx_map, &cookie);
	if (!ctx) {
		struct sock_context tmp;
		memset(&tmp, 0, sizeof(tmp));
		bpf_map_update_elem(&sock_ctx_map, &cookie, &tmp, BPF_NOEXIST);
		ctx = bpf_map_lookup_elem(&sock_ctx_map, &cookie);
		if (!ctx) {
			bpf_printk("did not get the context even after atempting to create it!");
			return 0;
		}
	}

	/* Check for socket close event */
	if (skops->op == BPF_SOCK_OPS_STATE_CB) {
		if (skops->args[1] == BPF_TCP_CLOSE) {
			bpf_map_delete_elem(&sock_map, &ctx->sock_map_index);
			bpf_map_delete_elem(&sock_ctx_map, &cookie);
		}
		return 0;
	}

	tcp = data;
	if (skops->family != AF_INET || (void *)(tcp + 1) > data_end) {
		return 0;
	}

	if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		ret = 0;
		conf = bpf_map_lookup_elem(&conn_monitor_config_map, &ret);
		if (!conf) {
			/* Should never happen */
			return 0;
		}
		if (tcp->dest == conf->port) {
			bpf_spin_lock(&count->lock);
			sk_index = count->value;
			/* Update this index as used */
			count->value = (count->value + 1) % MAX_CONN;
			bpf_spin_unlock(&count->lock);
			ctx->sock_map_index = sk_index;
			/* Add the socket to the map */
			ret = bpf_sock_map_update(skops, &sock_map, &sk_index, BPF_ANY);
			if (ret != 0) {
				bpf_printk("failed to insert into map");
				return 0;
			}
			/* Ask for sock close callback */
			ret = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
					BPF_SOCK_OPS_STATE_CB_FLAG);
		}
	}

	return 0;
}

// PROG TYPE: BPF_PROG_TYPE_CGROUP_SOCK
// ATTACH POINT: BPF_CGROUP_INET4_POST_BIND
// SEC("cgroup/post_bind4")
// int bind_v4_prog(struct bpf_sock_addr *ctx)
// {
// 	int ret;
// 	struct bpf_sock *sk;
// 	struct sock_context *skctx;
// 	struct count_sock *count;
// 	int sk_index;
//
// 	sk = ctx->sk;
// 	if (!sk)
// 		return 0;
//
// 	skctx = bpf_sk_storage_get(&sock_ctx_map, sk, NULL,
// 			BPF_LOCAL_STORAGE_GET_F_CREATE);
// 	if (!skctx) {
// 		/* Should never happen */
// 		return 0;
// 	}
//
// 	conf = bpf_map_lookup_elem(&conn_monitor_config_map, &ret);
// 	if (!conf) {
// 		/* Should never happen */
// 		return 0;
// 	}
//
// 	if (sk->family != AF_INET)
// 		return 0;
//
// 	if (ctx->type != SOCK_DGRAM)
// 		return 0;
//
// 	/* if (ctx->user_ip4 != bpf_htonl(SERV4_IP) || */
// 	/*     ctx->user_port != bpf_htons(SERV4_PORT)) */
// 	if (ctx->user_port != conf->port)
// 		return 0;
//
// 	count = bpf_map_lookup_elem(&count_sock_map, &ret);
// 	if (!count) {
// 		/* Should never happen */
// 		bpf_printk("failed to get count map");
// 		return 0;
// 	}
//
// 	bpf_spin_lock(&count->lock);
// 	sk_index = count->value;
// 	/* Update this index as used */
// 	count->value = (count->value + 1) % MAX_CONN;
// 	bpf_spin_unlock(&count->lock);
// 	/* Add the socket to the map */
// 	skctx->sock_map_index = sk_index;
// 	ret = bpf_sock_map_update(skops, &sock_map, &sk_index, BPF_ANY);
// 	if (ret != 0) {
// 		bpf_printk("failed to insert into map");
// 		return 0;
// 	}
//
// 	return 0;
// }

// SEC("cgroup/sock_release)
// int release_v4_prog(struct bpf_sock_addr *ctx)
// {
// 	int ret;
// 	struct bpf_sock *sk;
// 	struct count_sock *count;
// 	struct sock_context *skctx;
//
// 	sk = ctx->sk;
// 	if (!sk)
// 		return 0;
//
// 	skctx = bpf_sk_storage_get(&sock_ctx_map, sk, NULL,
// 			BPF_LOCAL_STORAGE_GET_F_CREATE);
// 	if (!skctx) {
// 		/* Should never happen */
// 		return 0;
// 	}
//
// 	conf = bpf_map_lookup_elem(&conn_monitor_config_map, &ret);
// 	if (!conf) {
// 		/* Should never happen */
// 		return 0;
// 	}
//
// 	if (sk->family != AF_INET)
// 		return 0;
//
// 	if (ctx->type != SOCK_DGRAM)
// 		return 0;
//
// 	/* if (ctx->user_ip4 != bpf_htonl(SERV4_IP) || */
// 	/*     ctx->user_port != bpf_htons(SERV4_PORT)) */
// 	if (ctx->user_port != conf->port)
// 		return 0;
//
// 	bpf_map_delete_elem(&sock_map, &skctx->sock_map_index);
//
// 	return 0;
// }
