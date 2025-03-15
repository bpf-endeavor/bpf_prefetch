#pragma once

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifdef __BPF__
#define __arena __attribute__((address_space(1)))
#else
// user-space
#define __arena
#endif
