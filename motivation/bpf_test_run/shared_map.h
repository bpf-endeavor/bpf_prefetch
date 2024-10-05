#ifndef SHARED_MAP_H
#define SHARED_MAP_H
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
struct find_map_res {
	int fd;
	size_t value_size;
	void *mmap_area;
};
static size_t roundup_page(size_t sz)
{
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	return ((sz + page_size - 1) / page_size) * page_size;
}
int get_shared_map(char *map_name, struct find_map_res *out)
{
	struct bpf_map_info map_info = {};
	uint32_t info_size = sizeof(map_info);
	unsigned int id = 0;
	int ret = 0;
	int map_fd;
	int flag = 0;
	while (!ret) {
		ret = bpf_map_get_next_id(id, &id);
		if (ret) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "can't get next map: %s%s", strerror(errno),
					errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}
		map_fd = bpf_map_get_fd_by_id(id);
		bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size);
		/* Compare the found map's name with our list of names */
		if (!strcmp(map_info.name, map_name)) {
			out->fd = map_fd;
			out->value_size = map_info.value_size;
			/* Memory map */
			if (map_info.map_flags & BPF_F_MMAPABLE) {
				const size_t map_sz = roundup_page((size_t)map_info.value_size * map_info.max_entries);
				void *m = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
				if (m == MAP_FAILED) {
					fprintf(stderr, "Failed to memory map 'ebpf MAP' size: %ld\n", map_sz);
					return 1;
				} else {
					out->mmap_area = m;
				}
			} else {
				out->mmap_area = NULL;
				/* printf("%s %x\n", map_info.name, map_info.map_flags); */
				/* printf("error: ring map is not mmapable\n"); */
				/* return 1; */
			}
			flag = 1;
			break;
		} else {
			close(map_fd);
		}
	}

	if (flag) {
		printf("found shared map!\n");
		/* printf("value size: %ld\n", ring_map_value_size); */
		/* for (int i = 0; i < 5 * ring_map_value_size; i++) { */
		/* 	printf("%02x ", ((unsigned char *)ring_map_area)[i]); */
		/* 	if (i % 16 == 15) */
		/* 		printf("\n"); */
		/* } */
		/* printf("\n"); */
		return 0;
	} else {
		fprintf(stderr, "Error: did not found the ring map!\n");
		return 1;
	}
}
#endif
