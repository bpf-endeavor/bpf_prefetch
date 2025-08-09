#pragma once

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifdef __BPF__
#define __arena __attribute__((address_space(1)))

/* emit instruction:
 * rX = rX .off = BPF_ADDR_SPACE_CAST .imm32 = (dst_as << 16) | src_as
 */
#ifndef bpf_addr_space_cast
#define bpf_addr_space_cast(var, dst_as, src_as)\
	asm volatile(".byte 0xBF;		\
			.ifc %[reg], r0;		\
			.byte 0x00;		\
			.endif;			\
			.ifc %[reg], r1;		\
			.byte 0x11;		\
			.endif;			\
			.ifc %[reg], r2;		\
			.byte 0x22;		\
			.endif;			\
			.ifc %[reg], r3;		\
			.byte 0x33;		\
			.endif;			\
			.ifc %[reg], r4;		\
			.byte 0x44;		\
			.endif;			\
			.ifc %[reg], r5;		\
			.byte 0x55;		\
			.endif;			\
			.ifc %[reg], r6;		\
			.byte 0x66;		\
			.endif;			\
			.ifc %[reg], r7;		\
			.byte 0x77;		\
			.endif;			\
			.ifc %[reg], r8;		\
			.byte 0x88;		\
			.endif;			\
			.ifc %[reg], r9;		\
			.byte 0x99;		\
			.endif;			\
			.short %[off];		\
			.long %[as]"		\
			: [reg]"+r"(var)		\
			: [off]"i"(BPF_ADDR_SPACE_CAST) \
			, [as]"i"((dst_as << 16) | src_as));
#endif
#define cast_kern(ptr) bpf_addr_space_cast(ptr, 0, 1)
#define cast_user(ptr) bpf_addr_space_cast(ptr, 1, 0)
#else
// user-space
#define __arena
#define cast_kern(x) 
#define cast_user(x) 
#endif

#ifndef arena_container_of
#define arena_container_of(ptr, type, member)                   \
        ({                                                      \
                void __arena *__mptr = (void __arena *)(ptr);   \
                ((type *)(__mptr - offsetof(type, member)));    \
        })
#endif

