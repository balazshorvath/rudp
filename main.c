#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include "rudp.h"

int main() {
    rudp_socket* sock_recv = rudp_bind("0.0.0.0", 1234);
    if (sock_recv == NULL)
        return -1;
    rudp_socket* sock_send = rudp_create("127.0.0.1", 1234);
    if (sock_send == NULL)
        return -1;

    rudp_session session = {.address = sock_send->address};
    rudp_send(sock_send, &session, "DARA", 5);

    sleep(2);
    char buffer[RUDP_PACKET_MAX_DATA_SIZE];

    printf("RECV (%d): %s\n", rudp_recv(rudp_accept(sock_recv), buffer, RUDP_PACKET_MAX_DATA_SIZE), buffer);
    rudp_close(sock_recv);
    rudp_close(sock_send);
    return 0;
}