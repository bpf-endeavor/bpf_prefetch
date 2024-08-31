XDP_FILTER=./xdp-tools/xdp-filter/xdp-filter

default: xdp-tools/xdp-filter $(XDP_FILTER)

xdp-tools/xdp-filter:
	git submodule update --init

$(XDP_FILTER): xdp-tools
	$(MAKE) -C ./xdp-tools/
