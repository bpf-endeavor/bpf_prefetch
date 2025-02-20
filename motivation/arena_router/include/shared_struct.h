#pragma once
#include <linux/bpf.h>
#include "compiler.h"

#define MAX_ENTRIES 2000000

typedef struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
} __packed my_key_t;

typedef struct {
    char msg[32];
} __packed my_value_t;

typedef struct {
    __u32 count_req;
    int reqs[0];
} __packed req_t;
