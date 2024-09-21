XDP_FILTER=./xdp-tools/xdp-filter/xdp-filter
NOCTORNAL=./noctornal/src/build/main

default: xdp-tools/xdp-filter $(XDP_FILTER) $(NOCTORNAL)

.PHONY: $(NOCTORNAL)

xdp-tools/xdp-filter:
	git submodule update --init

$(XDP_FILTER): xdp-tools
	$(MAKE) -C ./xdp-tools/

$(NOCTORNAL): noctornal
	if [ -z $$NET_IFACE ]; then echo Missing NET_IFACE; exit 123; fi
	ifindex=$$(ip -json addr show $$NET_IFACE | jq '.[0].ifindex') && \
	echo $$ifindex && \
	BPF_CFLAGS="-I $(CURDIR)/../deps/usr/include" \
	SERVER_LDFLAGS="-L $(CURDIR)/../deps/usr/lib64" \
	SERVER_CFLAGS="-I $(CURDIR)/../deps/usr/include -D IFINDEX=\"$$ifindex\"" \
	$(MAKE) -C ./noctornal/src/
