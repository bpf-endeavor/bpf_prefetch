/*
 * This file would have shared structus between sockops (connection monitor)
 * and userspace program (e.g., loader).
 * */
#ifndef __SOCKOPS_SHARED_H
#define __SOCKOPS_SHARED_H
/* Connection monitor configuration */
struct conn_monitor_config {
	unsigned int listen_ip;
	unsigned short port; /* Expect it to be in bigendian format */
};

#define SOCKMAP_PINNED_PATH "/sys/fs/bpf/mysockmap"

#endif
