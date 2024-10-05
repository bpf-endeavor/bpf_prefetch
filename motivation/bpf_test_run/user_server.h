#ifndef USER_SERVER_H
#define USER_SERVER_H
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int launch_server(void)
{
	int ret;
	ret = fork();
	if (ret < 0) {
		fprintf(stderr, "Failed to launch the server program (fork failed)\n");
		exit(EXIT_FAILURE);
	}
	if (ret == 0) {
		/* Child process */
		cpu_set_t cpu_cores;
		CPU_ZERO(&cpu_cores);
		CPU_SET(0, &cpu_cores);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
				&cpu_cores);
		char *server_binary = "./build/server";
		execl(server_binary, server_binary, "udp", (char *)NULL);
		fprintf(stderr, "Failed to launch the server program (exec failed)\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Sleep, so server have time to run...\n");
		sleep(3);
	}
	return ret;
}
#endif
