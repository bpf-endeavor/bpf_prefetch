#pragma once
#include <linux/bpf.h>
#include "compiler.h"

typedef struct {
    __u64 counter;
} entry_t;

typedef struct {
    __u32 dport;
} __packed my_key_t;

typedef struct {
    char msg[32];
} __packed my_value_t;

typedef struct {
    __u32 count_req;
    int reqs[0];
} __packed req_t;
