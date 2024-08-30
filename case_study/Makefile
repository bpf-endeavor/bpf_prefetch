XDP_FILTER=./xdp-tools/xdp-filter/xdp-filter

default: xdp-tools $(XDP_FILTER)

xdp-tools:
	git submodule update --init

$(XDP_FILTER): xdp-tools
	$(MAKE) - C ./xdp-tools/
