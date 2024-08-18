#ifndef _STRUCT_DEF_H
#define _STRUCT_DEF_H
typedef struct {
	unsigned int src_ip;
	unsigned short src_port;
	unsigned int dst_ip;
	unsigned short dst_port;
	unsigned char  protocol;
} __attribute__((packed)) flow_key_t;

typedef struct {
	unsigned int mapped_ip;
	unsigned long long int counter;
	unsigned int verdict;
}
/* __attribute__((aligned(32))) */
__attribute__((packed))
	flow_state_t;
#endif 
