#pragma once
#include <linux/bpf.h>
#include "compiler.h"

typedef struct {
    int data[2];
} __packed my_value_t;

typedef struct {
    __u32 count_req;
    my_value_t reqs[0];
} __packed req_t;

typedef struct {
    char msg[8];
} __packed resp_t;
