/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (C) 2020 Facebook, Inc. */

#ifndef __TESTING_HELPERS_H
#define __TESTING_HELPERS_H

#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>

#define __TO_STR(x) #x
#define TO_STR(x) __TO_STR(x)

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int parse_num_list(const char *s, bool **set, int *set_len);
#endif /* __TESTING_HELPERS_H */
