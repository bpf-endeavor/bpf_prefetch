#ifndef __RAND_H
#define __RAND_H
volatile static unsigned int seed = 1;
#define __rand_m 1664525
#define __rand_c 1013904223
static unsigned int __rand(void) {
	seed = (seed * __rand_m + __rand_c);
	return seed;
}
#endif
