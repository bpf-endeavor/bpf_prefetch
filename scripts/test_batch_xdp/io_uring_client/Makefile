CC=gcc
CFLAGS=-O2 -Wall
LDFLAGS=-luring

all: uring_udp_batch_client

uring_udp_batch_client: uring_udp_batch_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f uring_udp_batch_client

