#ifndef MAC_ADDR_H
#define MAC_ADDR_H
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int get_mac_addr(int ifindex, void *mac_addr)
{
	char ifname[IF_NAMESIZE];
	struct ifreq ifr = {};
	int fd, r;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	if (!if_indextoname(ifindex, ifname)) {
		r = -errno;
		goto end;
	}
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	r = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (r) {
		r = -errno;
		goto end;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6 * sizeof(char));
end:
	close(fd);
	return r;
}
#endif
