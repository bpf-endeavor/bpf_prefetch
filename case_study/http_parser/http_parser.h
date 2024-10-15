/*
* Functions for traversing request header and parsing HTTP protocol.
* @author Farbod Shahinfar
* */
#ifndef _HTTP_PARSER_2_H
#define _HTTP_PARSER_2_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "prefetching.h"

/* #define DEBUG 1 */
#ifdef DEBUG
#define BPF_TAG "web_server_offload: "
#define DUMP(x, args...) { const char fmt[] = BPF_TAG x; \
	bpf_trace_printk(fmt, sizeof(fmt), ##args); }
#else
#define DUMP(x, args...)
#endif

/* Make sure these types are defined */
#ifndef __u32
typedef unsigned char        __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
#endif

#ifndef NULL
#define NULL 0
#endif

#define CONTEXT struct xdp_md
#define sinline static inline __attribute__((__always_inline__))
#define mem_barrier asm volatile("": : :"memory")
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

/* Define limits and upper bounds */
#define MAX_CONN 1024
/* These constants are related to the request line
 * <method> <URI [shcema][host][path]> <version> */
#define MAX_URI_LEGNTH 255
#define MAX_HOST_LEGNTH 32
#define MAX_METHOD_LENGTH 8
#define MAX_SCHEMA_LENGTH 8
/* These constants are related to the header options <name> : <value> */
#define MAX_HEADER_NAME_LENGTH 32
#define MAX_HEADER_VALUE_LENGTH 128
/* Maximum number of lines that are parsed from header options */
#define MAX_HEADER_OPT_LINES 16

#define MAX_RESPONS_REASON 16

/* Constants related to the cache */
#define MAX_CACHE_DATA_SIZE 1000
#define MAX_CACHE_VALUES (1 << 7)

/* Some helper macros */
#define GET_DATA(ctx) (void *)(__u64)ctx->data
#define GET_DATAEND(ctx) (void *)(__u64)ctx->data_end

#define BOUND_CHECK(ptr, size, end, action) if (((void *)((char *)ptr + size)) > end) {action;}
#define BOUND_CHECK_INV(ptr, size, end) BOUND_CHECK(ptr, size, end, return INVALID)

#define IS_DIGIT(chr) (chr >= '0' && chr <= '9')
#define CHR_TO_INT(chr) ((chr) - '0')
#define LOWER_CASE(chr) (chr | 0x20)

#define COPY_HOST_NAME(dst, data, pctx, fail) {                      \
	char *base = data + (pctx->host_start_off & OFFSET_MASK);    \
	__u16 len = pctx->host_end_off - pctx->host_start_off;       \
	for (__u16 i = 0; i < len; i++) {                            \
		BOUND_CHECK(base + i, 1, data_end, fail);            \
		if (i > MAX_HOST_LEGNTH)                             \
			fail;                                        \
		dst[i] = base[i];                                    \
	}                                                            \
}

/* For masking offset related to the packet pointers
 * I am not sure why masking helps with verifier.
 * */
#define OFFSET_MASK 0x0fff

/* TODO: support REGEX? */
/* A location command: what to do for the given URI */
struct uri_cmd {
	__u32 cache_zone_index;
};

/* This structure is filled while parsing HTTP request */
struct parsing_ctx {
	__u16 head_off;         /* offset of last read byte */
	__u16 method_start_off; /* index of the fisrt upper case char */
	__u16 method_end_off;   /* index of space after method */

	__u16 uri_start_off;    /* start of the URI  [schema://][host][:port]/[path][?args][#comments] */
	__u16 uri_end_off;      /* end offset of the URI */

	__u8 http_major_ver;    /* major version value */
	__u8 http_minor_ver;    /* minor version value */

	/* Host may be outside of the URI. In this case it was set with "Host: Value" header option */
	__u16 host_start_off;   /* start of the host e.g. example.com or 192.168.1.1 */
	__u16 host_end_off;     /* end offset of the host */

	__u16 path_start_off;   /* start of the path */
	__u16 path_end_off;     /* end of the path */

	/* Flags */
	__u8 has_schema: 1;     /* the URI is an absolute path */
	__u8 all_header_parsed: 1;
	/* __u8 has_query: 1; */

	/* Some information */
	__u8 schema_type;
	__u16 port;
}; // __attribute__((__packed__));

struct update_cache_ctx {
	__u16 head_off;
	__u16 status_code;
	__u16 content_length; /* Payload length */
	__u16 total_length;   /* Total length of the response (payload + header) */
	__u32 max_age;

	/* Cache control */
	__u16 cache_ctrl_start_off;
	__u16 cache_ctrl_end_off;

	__u8 all_header_parsed: 1;
	__u8 has_authorization: 1;
	__u8 has_public: 1;
	__u8 continue_from_payload: 1;
};

struct cache_value {
	char data[MAX_CACHE_DATA_SIZE];
	__u16 length;
	__u8  is_valid;
	__u32 max_age;
};

struct conn_mark {
	__u8  is_marked;
	__u32 cache_index;
	__u32 redir_index;
};

enum RETURN_CODE {
	OKAY = 0,
	FAIL,
	INCOMPLETE,
	INVALID,
	UNSUPPORTED,
};

enum SUPPORTED_SCHEMA {
	HTTP = 100,
};

enum HEADER_OPT {
	OPT_NONE = 200,
	OPT_HOST,
	OPT_CACHE_CTL,
	OPT_AUTHORIZATION,
	OPT_CONTENT_LENGHT,
};

enum CACHE_CTRL_TYPE {
	NO_CACHE,
	PUBLIC_CACHE,
	PRIVATE_CACHE,
};

/*
 * parse the first line of HTTP request.
 * This step determines:
 *   1- the HTTP method
 *   2- The URI
 *   3- HTTP Version
 *
 * @param skb
 * @param pctx
 *
 * @returns OKAY on sucess, UNSUPPORTED if the request is not supported in this
 * implementatoin, or INVALID if something is wrong.
 * */
sinline int parse_http_request_line(CONTEXT *skb, __u16 _off, struct parsing_ctx *pctx)
{
	void *data;
	void *data_end;
	char *base;
	__u16 i;
	__u16 off;
	__u16 len;

	if (!pctx)
		return UNSUPPORTED;

	data = GET_DATA(skb);
	data_end = GET_DATAEND(skb);
	off = _off & OFFSET_MASK;
	base = (char *)data + off;
	P(&base[0]);
	P(&base[8]);
	if (base + 1 > data_end)
		return INVALID;


	/* off = pctx->head_off & OFFSET_MASK; */
	/* Find the start of the method */
	for (i = 0; i < 8; i++) {
		BOUND_CHECK_INV(base + i, 1, data_end)
		/* Allow request line to start after some empty lines */
		if (base[i] == '\n' || base[i] == '\r')
			continue;
		/* The first character of request lines should be an upper case letter */
		if (base[i] < 'A' || base[i] > 'Z') {
			DUMP("The first char is not uppercase letter");
			return INVALID;
		}
		/* Found the start of the HTTP method */
		off += i;
		pctx->method_start_off = off;
		goto method;
	}
	/* did not found the start of the method */
	DUMP("start of method not found");
	return INVALID;
method:
	/* Go to next char */
	off += 1;
	base = (char *)data + off;

	/* Find end of method */
	for (i = 0; i < MAX_METHOD_LENGTH; i++) {
		BOUND_CHECK_INV(base + i, 1, data_end)
			/* Upper case letters are allowed for method */
			if (base[i] >= 'A' && base[i] <= 'Z') {
				continue;
			}
		/* End of the method */
		if (base[i] == ' ') {
			off += i;
			pctx->method_end_off = off;
			goto check_method_supported;
		}
		/* Invalid character */
		DUMP("Method invalid character");
		return INVALID;
	}
	/* Did not found the end of method */
	DUMP("End of method not found");
	return INVALID;

check_method_supported:
	/* TODO should I merge checking supported operation with parsing ? */
	/* Check if method is supported */
	len = pctx->method_end_off - pctx->method_start_off;
	if (len != 3)
		return UNSUPPORTED;
	base = (char *)data + (pctx->method_start_off & OFFSET_MASK);
	P(&base[0]);
	P(&base[8]);
	BOUND_CHECK_INV(base, 3, data_end);
	if (! (base[0] == 'G' && base[1] == 'E' && base[2] == 'T')) {
		DUMP("Unsupported method");
		/* TODO check if NGINX supports this method otherwise return invalid*/
		return UNSUPPORTED;
	}
	/* ----------------------------------------------------------------- */

	/* Goto next char */
	off += 1;
	base = (char *)data + off;

	/* Find start of URI */
	/* barrier_var(base); */
	BOUND_CHECK_INV(base, 1, data_end);
	if (base[0] == ' ' || base[0] == '\r' || base[0] == '\n') {
		/* Multiple space between Method and URI */
		DUMP("Invalid character after method");
		return INVALID;
	}
	pctx->uri_start_off = off;
	off += 1;
	base = (char *)data + off;

	/* Find end of URI */
	for (i = 0; i < MAX_URI_LEGNTH; i++) { // 1
		P(&base[i+8]);
		BOUND_CHECK_INV(base + i, 1, data_end);
		if (base[i] == ' ') {
			off += i;
			pctx->uri_end_off = off;
			goto http_version;
		}
	}
	/* Did not found end of URI */
	DUMP("END of URI not found");
	return INVALID;

http_version:
	off += 1;
	base = (char *)data + off;
	/* End of line --> No HTTP version */
	BOUND_CHECK_INV(base, 2, data_end);
	if (base[0] == '\r' && base[1] == '\n') {
		pctx->http_major_ver = 0;
		pctx->http_minor_ver = 0;
		pctx->head_off = off;
		if (base[0] == '\r')
			pctx->head_off++;
		return OKAY;
	}
	/* NOT allowing multiple spaces */
	BOUND_CHECK_INV(base, 5, data_end);
	if (!  (base[0] == 'H' &&
				base[1] == 'T' &&
				base[2] == 'T' &&
				base[3] == 'P' &&
				base[4] == '/')) {
		/* Does not match the version structure */
		DUMP("Did not found HTTP/");
		return INVALID;
	}
	off += 5; // 4 (HTTP)  + 1 (/)
	base = (char *)data + off;

	/* Read HTTP version */
	BOUND_CHECK_INV(base, 5, data_end);
	/* Expecting value in the form of "d.d" where d is a digit */
	if (base[1] != '.' || !IS_DIGIT(base[0]) || !IS_DIGIT(base[2])) {
		DUMP("HTTP version format not exptected");
		return INVALID;
	}
	pctx->http_major_ver = CHR_TO_INT(base[0]);
	pctx->http_minor_ver = CHR_TO_INT(base[2]);

	/* off += 3; */
	/* base = data + off; */
	/* BOUND_CHECK_INV(base, 2, data_end); */
	if (base[3] != '\r' ||  base[4] != '\n') {
		DUMP("No end of line after HTTP version %u %u", base[3], base[4]);
		return INVALID;
	}
	if (base[3] == '\n')
		off += 4;
	else
		off += 5;
	pctx->head_off = off;

	/* TODO should I merge checking supported HTTP version with parsing ? */
	if (pctx->http_major_ver != 1 || pctx->http_minor_ver != 1) {
		/* Only support HTTP 1.1 */
		/* DUMP("Unsupported HTTP version"); */
		return UNSUPPORTED;
	}

	return OKAY;
}

/*
 * Parse URI of the HTTP request.
 *
 * It would determine the schema (http://), host address, port address,
 * resource path and args.
 *
 * @param skb
 * @param pctx
 *
 * @returns OKAY on success, UNSUPPORTED if the request is not supported in
 * this implementation or INVALID if somthing is wrong.
 * */
sinline int parse_http_uri(CONTEXT *skb, struct parsing_ctx *pctx)
{
	void *data;
	void *data_end;
	char *base;
	__u16 i;
	__u16 off;

	if (!pctx)
		return INVALID;

	data = GET_DATA(skb);
	data_end = GET_DATAEND(skb);
	off = (pctx->uri_start_off & OFFSET_MASK);
	base = data + off;

	BOUND_CHECK_INV(base, 1, data_end);
	if (base[0] == '/') {
		pctx->has_schema = 0;
		pctx->host_start_off = 0;
		pctx->host_end_off = 0;
		pctx->path_start_off = off;
		goto path;
	}

	/* Check the schema */
	BOUND_CHECK_INV(base, 7, data_end);
	pctx->has_schema = 1;
	if (!  (LOWER_CASE(base[0]) == 'h' &&
		LOWER_CASE(base[1]) == 't' &&
		LOWER_CASE(base[2]) == 't' &&
		LOWER_CASE(base[3]) == 'p' &&
		base[4] == ':' && base[5] == '/' && base[6] == '/')) {
		/* The schema is not supported */
		return UNSUPPORTED;
	}
	pctx->schema_type = HTTP;

	/* Check host address */
	off += 7;
	base = data + off;
	pctx->host_start_off = off;
	for (i = 0; i < MAX_HOST_LEGNTH; i++) {
		BOUND_CHECK_INV(base + i, 1, data_end);
		if (base[i] == ':') {
			off += i;
			pctx->host_end_off = off;
			goto port;
		} else if (base[i] == '/') {
			off += i;
			pctx->host_end_off = off;
			pctx->path_start_off = off;
			goto path;
		} else if (base[i] == '?') {
			off += i;
			pctx->host_end_off = off;
			pctx->path_start_off = 0;
			pctx->path_end_off = 0;
			goto args;
		} else if (base[i] == ' ') {
			off += i;
			pctx->host_end_off = off;
			/* TODO: Path is "/" */
			pctx->path_start_off = 0;
			pctx->path_end_off = 0;
			goto done;
		}
		/* TODO: is there not any other case (what if another character
		 * is observed ?) */
	}
	/* Failed to find the end of host probably the URI is longer than what
	 * is supported */
	return UNSUPPORTED;
port:
	off++;
	base = data + off;
	/* Read the port from URI */
	/* A port is maximum 65535. There are at most 5 digits and one
	 * character is need to determine the next state needed */
/* #pragma clang loop unroll(disable) */
	for (i = 0; i < 6; i++) {
		BOUND_CHECK_INV(base + i, 1, data_end);
		if (IS_DIGIT(base[i])) {
			pctx->port *= 10;
			pctx->port += CHR_TO_INT(base[i]);
		} else if (base[i] == '/') {
			off += i;
			pctx->path_start_off = off;
			goto path;
		} else if (base[i] == '?') {
			off += i;
			pctx->path_start_off = 0;
			pctx->path_end_off = 0;
			goto args;
		} else if (base[i] == ' ') {
			off += i;
			/* TODO: Path is "/" */
			pctx->path_start_off = 0;
			pctx->path_end_off = 0;
			goto done;
		} else {
			return INVALID;
		}
	}
	/* End of port not found! */
	return INVALID;
path:
	/* Starting slash ("/") has been observed before reaching here */
	off++;
	/* NOTE: It is puzzling that line below will not pass the verifier but
	 * the next line does. Also it was not a problem until I changed
	 * somewhere else in the program. */
	/* base = data + off; */
	base = data + (off & OFFSET_MASK);
	/* Read resource path from URI */
/* #pragma clang loop unroll(disable) */
	for (i = 0; i < MAX_URI_LEGNTH; i++) { // 2
		BOUND_CHECK_INV(base + i, 1, data_end);
		switch (base[i]) {
			case ' ':
			case '?':
			case '#': 
			case '\n':
			case '\r':
				off += i;
				pctx->path_end_off = off;
				goto args;
			default:
				continue;
		}
	}
	/* Failed to find the end of path */
	return UNSUPPORTED;
args:
	/* Read args (string-query) */
	/* TODO: do not care about args write now */

done:
	return OKAY;
}

/*
 * Parse one line of HTTP header
 * */
sinline int parse_http_header_line(CONTEXT *skb,
		struct parsing_ctx *pctx, enum HEADER_OPT *_opt)
{
	void *data;
	void *data_end;
	char *base;
	__u16 start, end; /* Start and end of the name/value */
	__u16 len;
	__u16 off;
	__u16 i;

	if (!pctx || !_opt)
		return INVALID;
	/* if (pctx->all_header_parsed) */
	/* 	return FAIL; /1* All of the header has been parsed *1/ */

	data = GET_DATA(skb);
	data_end = GET_DATAEND(skb);
	off = pctx->head_off & OFFSET_MASK;
	base = data + off;

	BOUND_CHECK_INV(base, 2, data_end);
	if (base[0] == '\n') {
		pctx->all_header_parsed = 1;
		pctx->head_off += 1;
		return OKAY;
	}
	else if (base[0] == '\r') {
		if (base[1] == '\n') {
			pctx->all_header_parsed = 1;
			pctx->head_off += 2;
			return OKAY;
		} else {
			return INVALID;
		}
	}

	len = 0;
	end = 0;
	start = off;
#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_HEADER_NAME_LENGTH; i++) {
		BOUND_CHECK_INV(base + i, 2, data_end);
		if (base[i] == ':') {
			off += i;
			end = off;
			/* goto check_method_name; */
			break;
		} else if (base[i] == ' ') {
			/* Method name ended. we are also looking for ":" */
			off += i;
			end = off;
			if (base[i + 1] != ':') {
				/* Does not support mutliple space after method name */
				return INVALID;
			}
			off += 1;
			break;
		}
		len++;
	}
	/* Did not found the end of header name */
	if (end == 0) {
		/* DUMP("Method end not found"); */
		return INVALID;
	}

	/* TODO: This way of checking the option name is ridiculous */
	/* TODO: can I implement a trie in the eBPF */
	/* Currently only interested about "Host" and "Cache-Control" option */
	base = data + (start & OFFSET_MASK);
	if (len == 4) {
		BOUND_CHECK_INV(base, 4, data_end);
		if (    LOWER_CASE(base[0]) == 'h' &&
			LOWER_CASE(base[1]) == 'o' &&
			LOWER_CASE(base[2]) == 's' &&
			LOWER_CASE(base[3]) == 't'
		   ) {
			*_opt = OPT_HOST;
		}
	}

	/* Find the host value */
	off += 1; // next character after ":"
	base = data + (off & OFFSET_MASK);
	BOUND_CHECK_INV(base, 2, data_end);
	if (base[0] == ' ') {
		if( base[1] == ' ') {
			/* Does not support multiple space after ":" */
			return INVALID;
		}
		off += 1;
		start = off;
		base++;
	} else {
		start = off;
	}

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_HEADER_VALUE_LENGTH; i++) {
		/* i = i & OFFSET_MASK; */
		BOUND_CHECK_INV(base + i, 1, data_end);
		if (base[i] == '\n') {
			off += i;
			end = off;
			goto found_value;
		}
	}
	/* Did not found end of the value */
	return INVALID;

found_value:
	off++;
	if (*_opt == OPT_HOST) {
		pctx->host_start_off = start;
		pctx->host_end_off = end;
		/* DUMP("Update host value from header option!"); */
	}
	pctx->head_off = off;
	return OKAY;
}

/* int parse_http_header_line_egress(struct sk_msg_md *msg, */
/* 		struct update_cache_ctx *pctx, enum HEADER_OPT *_opt) */
/* { */
/* 	void *data; */
/* 	void *data_end; */
/* 	__u16 off, len, start, end, i; */
/* 	__u64 value; */
/* 	char *base; */
/* 	if (!pctx || !_opt) */
/* 		return INVALID; */

/* 	data = GET_DATA(msg); */
/* 	data_end = GET_DATAEND(msg); */
/* 	off = pctx->head_off & OFFSET_MASK; */
/* 	base = data + off; */

/* 	BOUND_CHECK_INV(base, 2, data_end); */
/* 	if (base[0] == '\n') { */
/* 		pctx->all_header_parsed = 1; */
/* 		pctx->head_off += 1; */
/* 		return OKAY; */
/* 	} */

/* 	if (base[0] == '\r') { */
/* 		if (base[1] == '\n') { */
/* 			pctx->all_header_parsed = 1; */
/* 			pctx->head_off += 2; */
/* 			return OKAY; */
/* 		} else { */
/* 			/1* DUMP("\\r with out \\n"); *1/ */
/* 			return INVALID; */
/* 		} */
/* 	} */

/* 	len = 0; */
/* 	end = 0; */
/* 	start = off; */
/* #pragma clang loop unroll(disable) */
/* 	for (i = 0; i < MAX_HEADER_NAME_LENGTH; i++) { */
/* 		BOUND_CHECK_INV(base + i, 2, data_end); */
/* 		if (base[i] == ':') { */
/* 			off += i; */
/* 			end = off; */
/* 			/1* goto check_method_name; *1/ */
/* 			break; */
/* 		} else if (base[i] == ' ') { */
/* 			/1* Method name ended. we are also looking for ":" *1/ */
/* 			off += i; */
/* 			end = off; */
/* 			if (base[i + 1] != ':') { */
/* 				/1* Does not support mutliple space after method name *1/ */
/* 				return INVALID; */
/* 			} */
/* 			off += 1; */
/* 			break; */
/* 		} */
/* 		len++; */
/* 	} */
/* 	/1* Did not found the end of header name *1/ */
/* 	if (end == 0) { */
/* 		/1* DUMP("end of option name not found"); *1/ */
/* 		return INVALID; */
/* 	} */
/* 	if (len == 13) { */
/* 		BOUND_CHECK_INV(base, 13, data_end); */
/* 		if (LOWER_CASE(base[0]) == 'c' */
/* 				&& LOWER_CASE(base[1]) == 'a' */
/* 				&& LOWER_CASE(base[2]) == 'c' */
/* 				&& LOWER_CASE(base[3]) == 'h' */
/* 				&& LOWER_CASE(base[4]) == 'e' */
/* 				&&            base[5]  == '-' */
/* 				&& LOWER_CASE(base[6]) == 'c' */
/* 				&& LOWER_CASE(base[7]) == 'o' */
/* 				&& LOWER_CASE(base[8]) == 'n' */
/* 				&& LOWER_CASE(base[9]) == 't' */
/* 				&& LOWER_CASE(base[10]) == 'r' */
/* 				&& LOWER_CASE(base[11]) == 'o' */
/* 				&& LOWER_CASE(base[12]) == 'l' */
/* 		   ) { */
/* 			*_opt = OPT_CACHE_CTL; */
/* 		} else if ( LOWER_CASE(base[0]) == 'a' */
/* 				&& LOWER_CASE(base[1]) == 'u' */
/* 				&& LOWER_CASE(base[2]) == 't' */
/* 				&& LOWER_CASE(base[3]) == 'h' */
/* 				&& LOWER_CASE(base[4]) == 'o' */
/* 				&& LOWER_CASE(base[5]) == 'r' */
/* 				&& LOWER_CASE(base[6]) == 'i' */
/* 				&& LOWER_CASE(base[7]) == 'z' */
/* 				&& LOWER_CASE(base[8]) == 'a' */
/* 				&& LOWER_CASE(base[9]) == 't' */
/* 				&& LOWER_CASE(base[10]) == 'i' */
/* 				&& LOWER_CASE(base[11]) == 'o' */
/* 				&& LOWER_CASE(base[12]) == 'n' */
/* 			  ) { */
/* 			*_opt = OPT_AUTHORIZATION; */
/* 			pctx->has_authorization = 1; */
/* 		} */
/* 	} else if(len == 14) { */
/* 		BOUND_CHECK_INV(base, 14, data_end); */
/* 		if (LOWER_CASE(base[0]) == 'c' */
/* 				&& LOWER_CASE(base[1]) == 'o' */
/* 				&& LOWER_CASE(base[2]) == 'n' */
/* 				&& LOWER_CASE(base[3]) == 't' */
/* 				&& LOWER_CASE(base[4]) == 'e' */
/* 				&& LOWER_CASE(base[5]) == 'n' */
/* 				&& LOWER_CASE(base[6]) == 't' */
/* 				&&            base[7]  == '-' */
/* 				&& LOWER_CASE(base[8]) == 'l' */
/* 				&& LOWER_CASE(base[9]) == 'e' */
/* 				&& LOWER_CASE(base[10]) == 'n' */
/* 				&& LOWER_CASE(base[11]) == 'g' */
/* 				&& LOWER_CASE(base[12]) == 't' */
/* 				&& LOWER_CASE(base[13]) == 'h' */
/* 		   ) { */
/* 			*_opt = OPT_CONTENT_LENGHT; */
/* 		} */
/* 	} */

/* 	off += 1; // next character after ":" */
/* 	base = data + (off & OFFSET_MASK); */
/* 	BOUND_CHECK_INV(base, 2, data_end); */
/* 	if (base[0] == ' ') { */
/* 		if(base[1] == ' ') { */
/* 			/1* Does not support multiple space after ":" *1/ */
/* 			/1* DUMP("does not support multiple space after :") *1/ */
/* 			return INVALID; */
/* 		} */
/* 		off += 1; */
/* 		start = off; */
/* 		base++; */
/* 	} else { */
/* 		start = off; */
/* 	} */

/* #pragma clang loop unroll(disable) */
/* 	for (i = 0; i < MAX_HEADER_VALUE_LENGTH; i++) { */
/* 		BOUND_CHECK_INV(base + i, 1, data_end); */
/* 		if (base[i] == '\n') { */
/* 			off += i; */
/* 			end = off; */
/* 			goto found_value; */
/* 		} */
/* 	} */
/* 	/1* Did not found end of the value *1/ */
/* 	/1* DUMP("did not found end of value\n"); *1/ */
/* 	return INVALID; */

/* found_value: */
/* 	if (*_opt == OPT_CACHE_CTL) { */
/* 		pctx->cache_ctrl_start_off = start; */
/* 		pctx->cache_ctrl_end_off = end; */
/* 	} else if (*_opt == OPT_CONTENT_LENGHT) { */
/* 		len = end - start; */
/* 		if (len > 4) { */
/* 			/1* Content Length is more than we can cache *1/ */
/* 			return INVALID; */
/* 		} */
/* 		value = 0; */
/* 		for (i = 0; i < len; i++) { */
/* 			if (IS_DIGIT(base[i])) */
/* 				value = (value * 10) + CHR_TO_INT(base[i]); */
/* 			else */
/* 				break; */
/* 		} */
/* 		pctx->content_length = value; */
/* 		/1* DUMP("update content length value: %d", pctx->content_length); *1/ */
/* 	} */
/* 	off++; */
/* 	pctx->head_off = off; */
/* 	return OKAY; */
/* } */

/* int parse_http_response_line(struct sk_msg_md *msg, struct update_cache_ctx *pctx) */
/* { */
/* 	void *data; */
/* 	void *data_end; */
/* 	char *base; */
/* 	__u16 i; */

/* 	if (!pctx) */
/* 		return INVALID; */

/* 	data = GET_DATA(msg); */
/* 	data_end = GET_DATAEND(msg); */
/* 	base = data; */

/* 	BOUND_CHECK_INV(base, 12, data_end); */
/* 	if (!(base[0] == 'H' */
/* 				&& base[1] == 'T' */
/* 				&& base[2] == 'T' */
/* 				&& base[3] == 'P' */
/* 				&& base[4] == '/' */
/* 				&& base[5] == '1' */
/* 				&& base[6] == '.' */
/* 				&& base[7] == '1' */
/* 				&& base[8] == ' ')) { */
/* 		DUMP("Not HTTP/") */
/* 			return INVALID; */
/* 	} */

/* 	if (!IS_DIGIT(base[9]) || !IS_DIGIT(base[10]) || !IS_DIGIT(base[11])) { */
/* 		DUMP("Not status number") */
/* 			return INVALID; */
/* 	} */

/* 	pctx->status_code = (CHR_TO_INT(base[9]) * 100) + */
/* 		(CHR_TO_INT(base[10]) * 10) + CHR_TO_INT(base[11]); */
/* 	/1* Find end of response line *1/ */
/* 	for (i = 12; i < 12 + MAX_RESPONS_REASON; i++) { */
/* 		BOUND_CHECK_INV(base + i, 1, data_end); */
/* 		if (base[i] == '\n') { */
/* 			pctx->head_off = i + 1; */
/* 			goto okay; */
/* 		} */
/* 	} */
/* 	/1* Did not found end of reponse line *1/ */
/* 	DUMP("end of line not found") */
/* 		return INVALID; */
/* okay: */
/* 	return OKAY; */
/* } */
#endif
