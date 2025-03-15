/* A memory allocator for my Arena data-structures
 * Farbod Shahinfar - Feburary 2025
 * */
#pragma once
#include <linux/bpf.h>
#include "stddef.h"
#include "arena_common.h"

#define MAGIC_WORD 0x7480d321
#define MAX_SIZE (1 << 30)
#define MIN_SIZE (sizeof(mem_region_t) + 64)

struct mem_region;
typedef struct mem_region mem_region_t;
typedef struct {
    mem_region_t *first;
} mem_handle_t;

struct mem_region {
    __u32 magic;
    __u64 size;
    mem_region_t *next;
    /* for free operation */
    mem_handle_t *handle;
};

int create_mem_region_obj(void *area, __u64 sz, mem_handle_t *m)
{
    m->first = NULL;
    if (sz < MIN_SIZE)
        return -1;

    mem_region_t *obj = area;
    obj->magic = MAGIC_WORD;
    obj->size = sz - sizeof(mem_region_t);
    obj->next = NULL;
    obj->handle = m;
    m->first = obj;
    return 0;
}

void *just_alloc(mem_handle_t *r, __u64 sz)
{
    if (r == NULL || r->first == NULL || sz == 0 || sz > MAX_SIZE)
        return NULL;

    __u64 required_size = sz;

    /* Find a contiguos region of memory */
    mem_region_t **prev_ptr = &r->first;
    mem_region_t *ptr = r->first;
    do {
        if (ptr->size >= required_size) {
            break;
        }
        prev_ptr = &ptr->next;
        ptr = ptr->next;
    } while(ptr != NULL);

    if (ptr == NULL) {
        /* Did not found a large enough region */
        return NULL;
    }

    void *to_be_used = ptr + 1;

    /* decide how to update the free list. If this region has enough emptry
     * space, create a new memregion. Otherwise connect to the next region */
    mem_region_t *new_next = NULL;
    __u64 remaining_sz = ptr->size - sz;
    if (remaining_sz > MIN_SIZE) {
        new_next = (mem_region_t *)(to_be_used + sz);
        new_next->magic = MAGIC_WORD;
        new_next->size = ptr->size - sz - sizeof(mem_region_t);
        new_next->next = ptr->next;
        new_next->handle = r;

        /* The current region has been split, so have less size */
        ptr->size = sz;
    } else {
        new_next = ptr->next;
    }
    /* Connect the previous memory region to the next */
    *prev_ptr = new_next;

    ptr->next = NULL;

    return to_be_used; 
}

int just_free(void *p)
{
    if (p == NULL)
        return 0;

    mem_region_t *m = (mem_region_t *)(p -  sizeof(mem_region_t));
    if (m->magic != MAGIC_WORD) {
        /* Something is wrong */
        return -1;
    }

    /* Find the first mem_region in the free list that is before this pointer */
    mem_region_t *ptr = m->handle->first;
    mem_region_t *before = NULL;
    while (ptr != NULL && ptr < m) {
        before = ptr;
        ptr = ptr->next;
    }

    if (before == NULL) {
        /* there are no memory region before freed region (new root) */
        m->next = m->handle->first;
        m->handle->first = m;
    } else {
        /* we find a memory region before the one we are freeing */
        m->next = before->next;
        before->next = m;
    }

    /* Check if can coalesce memory */
    void *tmp = (void *)(m) + sizeof(mem_region_t) + m->size;
    if (tmp == m->next) {
        m->next->magic = 0;
        m->size += m->next->size + sizeof(mem_region_t);
    }
    return 0;
}

#ifndef __BPF__
#define COUNT_OBJ(A, B) ((((A) + (B)) - 1) / (B))
#define ROUND_UP(N, S) (COUNT_OBJ(N, S) * (S))
int userspace_alloc_pages(void *area, __u64 count_pages)
{
    /* Make sure the requested number of pages are allocated. Try to access
     * them to make sure. If it is not allocated the fault signal should
     * cause the kernel to allocate it.  */
    __u8 *ptr = area;
    for (__u64 i = 0; i < count_pages; i++) {
        *(__u32 *)&ptr[PAGE_SIZE * i + 0] = 0;
    }
    return 0;
}
#endif
