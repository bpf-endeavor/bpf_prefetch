#ifndef BPF_STATS_H
#define BPF_STATS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#define _FILE_PATH_BUF_SZ 256
#define _DATA_BUF_SZ 1024
#define _VAL_BUF_SZ 256
struct fd_info {
	int prog_type;
	int prog_jited;
	int memlock;
	int prog_id;
	time_t run_time_ns;
	size_t run_cnt; 
	size_t verified_insns;
};

char *_parse_fdinfo_line(char *cur, struct fd_info *info)
{
	char keybuf[_VAL_BUF_SZ];
	char valbuf[_VAL_BUF_SZ];
	char *t;
	size_t len;
	t = index(cur, ':');
	if (t == NULL) {
		fprintf(stderr, "Failed to parse the fdinfo (1)\n");
		exit(EXIT_FAILURE);
	}
	len = t - cur;
	if (len >= _VAL_BUF_SZ) {
		fprintf(stderr, "The buffers used for parsing fdinfo are small (1)\n");
		exit(EXIT_FAILURE);
	}
	memcpy(keybuf, cur, len);
	keybuf[len] = '\0';
	cur = t + 1;
	while (*cur == ' ' || *cur == '\t') {
		/* skip white space */
		cur++;
	}
	t = index(cur, '\n');
	if (t == NULL) {
		fprintf(stderr, "Failed to parse the fdinfo (2)\n");
		exit(EXIT_FAILURE);
	}
	len = t - cur;
	if (len >= _VAL_BUF_SZ) {
		fprintf(stderr, "The buffers used for parsing fdinfo are small (2)\n");
		exit(EXIT_FAILURE);
	}
	memcpy(valbuf, cur, len);
	valbuf[len] = '\0';

	/* printf("%s | %s\n", keybuf, valbuf); */
	if(strcmp(keybuf, "prog_type") == 0) {
		info->prog_type = atoi(valbuf);
	} else if(strcmp(keybuf, "prog_jited") == 0) {
		info->prog_jited = atoi(valbuf);
	} else if(strcmp(keybuf, "memlock") == 0) {
		info->memlock = atoi(valbuf);
	} else if(strcmp(keybuf, "prog_id") == 0) {
		info->prog_id = atoi(valbuf);
	} else if(strcmp(keybuf, "run_time_ns") == 0) {
		info->run_time_ns = atoi(valbuf);
	} else if(strcmp(keybuf, "run_cnt") == 0) {
		info->run_cnt = atoi(valbuf);
	} else if(strcmp(keybuf, "verified_insns") == 0) {
		info->verified_insns = atoi(valbuf);
	}
	/* I expect to cur to point to the next line */
	cur = t + 1;
	return cur;
}

void _parse_fdinfo_text(char *buf, size_t size, struct fd_info *info)
{
	char *cur;
	char *t;
	size_t len;
	size_t parsed = 0;
	cur = buf;
	while (parsed < size) {
		t = _parse_fdinfo_line(cur, info);
		len = t - cur;
		parsed += len;
		cur = t;
	}
}

int bpf_read_fdinfo(int bpf_prog_fd, struct fd_info *info)
{
	int fd;
	int ret;
	char file_path[_FILE_PATH_BUF_SZ];
	char buf[_DATA_BUF_SZ];
	pid_t pid;
	pid = getpid();
	ret = snprintf(file_path, _FILE_PATH_BUF_SZ,
			"/proc/%d/fdinfo/%d", pid, bpf_prog_fd);
	if (ret >= _FILE_PATH_BUF_SZ) {
		fprintf(stderr, "Not enough buffer size for bpf fdinfo path\n");
		return -1;
	}
	fd = open(file_path, O_RDONLY);
	if (fd < 1) {
		perror("Failed to open the fdinfo file\n");
		return -1;
	}
	ret = read(fd, buf, _DATA_BUF_SZ);
	if (ret < 0) {
		perror("Failed to read fdinfo file\n");
		return -1;
	}
	/* printf("%s\n", buf); */
	_parse_fdinfo_text(buf, ret, info);
	/* printf("prog_type: %d\n", info->prog_type); */
	/* printf("prog_jited: %d\n", info->prog_jited); */ 
	/* printf("memlock: %d\n", info->memlock); */ 
	/* printf("prog_id: %d\n", info->prog_id); */ 
	/* printf("run_time_ns: %ld\n", info->run_time_ns); */ 
	/* printf("run_cnt : %ld\n", info->run_cnt); */ 
	/* printf("verified_insns: %ld\n", info->verified_insns); */ 
	return 0;
}
#endif
