#pragma once

#ifndef NULL
#define NULL 0
#endif

#ifndef _BITS_STDINT_INTN_H
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long long int int64_t;
#endif

#ifndef bool
typedef uint8_t bool;
enum boolean_value {
	false = 0,
	true = 1,
};
#endif
