#ifndef RUNNER_ARGS_H
#define RUNNER_ARGS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <net/if.h>
#include <assert.h>

struct parameters {
	char *binary_path;
	char *input_path;
	size_t repeat;
	char *progname;
	int cross_test;
	int xdp;
	char *ifname;
	int ifindex;
	char *sender_ip;
	char *receiver_ip;
	size_t payload_size;
	int cpu_core;
};
extern struct parameters args;

void usage(void) {
	printf("loader:\n"
		"  --binary     -b   path to binary file\n"
		"  --repeat     -r   [default 10^4]\n"
		"  --prog-name  -p   [default prog]\n"
		"  --cross-test -x   run a userspace server for \n"
		"                    testing the kernel/user crossing.\n"
		"  --xdp             run xdp program\n"
		"  --iface     -i    interface to use in cross test\n"
		"  --sender          ip of the sender (when running cross-test)\n"
		"  --receiver        ip of receiver (when running cross-test)\n"
		"  --input           path to the benchmark input file. it is\n"
		"                    used to fill the payload of the packet\n"
		"  --cpu       -C    CPU core to run on\n"
		"  --size            The size of the payload in bytes [default 16]\n"
		"  --help      -h\n"
	);
}

void parse_args(int argc, char *argv[]) {
	int ret;

	struct option long_opts[] = {
		{"help",       no_argument,       NULL, 'h'},
		{"binary",     required_argument, NULL, 'b'},
		{"input",      required_argument, NULL, 128},
		{"repeat",     required_argument, NULL, 'r'},
		{"prog-name",  required_argument, NULL, 'p'},
		{"cross-test", no_argument,       NULL, 'x'},
		{"iface",      required_argument, NULL, 'i'},
		{"xdp",        no_argument,       NULL, 129},
		{"sender",     required_argument, NULL, 130},
		{"receiver",   required_argument, NULL, 131},
		{"cpu",        required_argument, NULL, 'C'},
		{"size",       required_argument, NULL, 132},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};

	/* Default values */
	args.input_path = "./inputs/payload.txt";
	args.repeat = 10000;
	args.progname = "prog";
	args.cross_test = 0;
	args.xdp = 0;
	args.sender_ip = "192.168.1.2";
	args.receiver_ip = "192.168.1.1";
	args.payload_size = 16;
	args.cpu_core = 0;

	while (1) {
		ret = getopt_long(argc, argv, "xhb:i:r:p:C:", long_opts, NULL);
		if (ret == -1)
			break;
		switch(ret) {
			case 'b':
				args.binary_path = optarg;
				break;
			case 128:
				args.input_path = optarg;
				break;
			case 'r':
				args.repeat = atoi(optarg);
				break;
			case 'p':
				args.progname = optarg;
				break;
			case 'x':
				args.cross_test = 1;
				break;
			case 'i':
				args.ifname = strdup(optarg);
				args.ifindex = if_nametoindex(optarg);
				printf("selected interface %s: %d\n", args.ifname, args.ifindex);
				assert(args.ifindex > 0);
				break;
			case 'C':
				args.cpu_core = atoi(optarg);
				break;
			case 129:
				args.xdp = 1;
				break;
			case 130:
				args.sender_ip = strdup(optarg);
				break;
			case 131:
				args.receiver_ip = strdup(optarg);
				break;
			case 132:
				args.payload_size = atoi(optarg);
				break;
			case 'h':
				usage();
				exit(0);
				break;
			default:
				usage();
				exit(EXIT_FAILURE);
				break;
		}
	}

	if (args.xdp && args.cross_test) {
		fprintf(stderr, "Cannot configure both cross-test and xdp together.\n");
		exit(EXIT_FAILURE);
	}


	if ((args.xdp || args.cross_test) && args.ifindex < 1) {
		fprintf(stderr, "You should specifiy an interface.\n");
		exit(EXIT_FAILURE);
	}
}
#endif
