#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define DEST_IP "192.168.122.245"  // Change as needed
#define DEST_PORT 8080         // Change as needed

int main() {
    struct io_uring_sqe *sqe;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    if (inet_pton(AF_INET, DEST_IP, &dest.sin_addr) != 1) {
        perror("inet_pton");
        close(sock);
        return 1;
    }
    // Connect the UDP socket to the destination address
    if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, 0) < 0) {
        perror("io_uring_queue_init");
        close(sock);
        return 1;
    }

    const char buf1[] = "hello world! this is a message";
    const int send = 32;
    int sent;
    for (sent = 0; sent < send; sent++) {
        sqe = io_uring_get_sqe(&ring);
        if (sqe == NULL) {
            break;
        }
        io_uring_prep_send(sqe, sock, buf1, sizeof(buf1), 0);
    }

    // failed to send anythign?!
    if (sent == 0) {
        io_uring_queue_exit(&ring);
        close(sock);
        return 1;
    }

    // Submit both at once
    int ret = io_uring_submit(&ring);
    if (ret < 2) {
        fprintf(stderr, "Failed to submit both packets: submitted %d\n", ret);
        io_uring_queue_exit(&ring);
        close(sock);
        return 1;
    }

    // Optionally, wait for completions
    struct io_uring_cqe *cqe;
    for (int i = 0; i < sent; i++) {
        if (io_uring_wait_cqe(&ring, &cqe) < 0) {
            perror("io_uring_wait_cqe");
            io_uring_queue_exit(&ring);
            close(sock);
            return 1;
        }
        if ((int)cqe->res < 0) {
            fprintf(stderr, "Send failed: %s\n", strerror(-cqe->res));
        } else {
            printf("Sent %d bytes\n", cqe->res);
        }
        io_uring_cqe_seen(&ring, cqe);
    }

    // Prepare to receive two responses
    char recv_buf1[2048];
    for (int i = 0; i < sent; i++) {
retry_2:
        sqe = io_uring_get_sqe(&ring);
        if (sqe == NULL) {
            goto retry_2;
        }
        io_uring_prep_recv(sqe, sock, recv_buf1, sizeof(recv_buf1), 0);
        ret = io_uring_submit(&ring);

        // Submit both receive requests
        if (ret < 1) {
            fprintf(stderr, "Failed to submit both receive requests: submitted %d\n", ret);
            io_uring_queue_exit(&ring);
            close(sock);
            return 1;
        }

        if (io_uring_wait_cqe(&ring, &cqe) < 0) {
            perror("io_uring_wait_cqe (recv)");
            io_uring_queue_exit(&ring);
            close(sock);
            return 1;
        }
        if ((int)cqe->res < 0) {
            fprintf(stderr, "Receive failed: %s\n", strerror(-cqe->res));
        } else {
            char *buf = recv_buf1;
            int len = cqe->res;
            printf("Received %d bytes: ", len);
            for (int j = 0; j < len; j++)
                printf("%c", buf[j]);
            printf("\n");
        }
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);
    close(sock);
    return 0;
}

