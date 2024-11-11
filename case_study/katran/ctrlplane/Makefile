CC = clang
CFLAGS = -O2 -g -Wall -I ../../../deps/usr/include
LDFLAGS = -lbpf -lelf -lz
SOURCE = $(wildcard *.c)
HEADERS = $(wildcard *.h)
OUTPUT = katctrl

default: $(OUTPUT)

$(OUTPUT): $(SOURCE) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCE) $(LDFLAGS)
