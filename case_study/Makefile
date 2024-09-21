XDP_FILTER=./xdp-tools/xdp-filter/xdp-filter
NOCTORNAL=./noctornal/src/build/main

default: xdp-tools/xdp-filter $(XDP_FILTER) $(NOCTORNAL)

xdp-tools/xdp-filter:
	git submodule update --init

$(XDP_FILTER): xdp-tools
	$(MAKE) -C ./xdp-tools/

$(NOCTORNAL): noctornal
	BPF_CFLAGS="-I $(CURDIR)/../deps/usr/include" \
	SERVER_LDFLAGS="-L $(CURDIR)/../deps/usr/lib64" \
	SERVER_CFLAGS="-I $(CURDIR)/../deps/usr/include" \
	$(MAKE) -C ./noctornal/src/
