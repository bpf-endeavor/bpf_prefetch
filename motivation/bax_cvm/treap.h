#ifndef _BAX_CVM_TREAP_H
#define _BAX_CVM_TREAP_H
#include <stdint.h>
typedef struct ipv4_lpm_key {
    uint32_t data;
} __attribute__((packed)) my_key_t;
// static_assert (sizeof(my_key_t) == 4);

/* bring Treap data-structure from the library */
// #define TREAP_KEY_SIZE sizeof(my_key_t) // default key-size is 4; if
// defining this also should provide comparison functions
#define TREAP_MAX_SIZE (1 << 14)
#define TREAP_MAX_HEIGHT 64
#include "arena-ds/treap.h"
#include "arena-ds/fixed-point/fp.h"
#endif
