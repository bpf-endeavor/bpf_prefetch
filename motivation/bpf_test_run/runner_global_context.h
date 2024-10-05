#ifndef RUNNER_GLOBAL_CONTEXT_H
#define RUNNER_GLOBAL_CONTEXT_H
struct program_context {
	struct bpf_object *bpfobj;
	struct bpf_program *prog;
	int prog_fd;
	double last_test_duration;
	int live;
	int server_pid;
};
extern struct program_context context;
#endif
