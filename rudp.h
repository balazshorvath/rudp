//
// Created by oryk on 9/1/18.
//

#ifndef RUDP_RUDP_H
#define RUDP_RUDP_H

#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SLIDING_FOR(window_start, window_size, max_value) for(int i = 0, sliding = window_start; i < window_size; ++i, sliding = (i + window_start) % max_value)
#define INCREMENT_SLIDING(value, max_value) (value = (value + 1) % max_value)

#ifndef MAX
#define MAX(x, y) ((x > y) ? x : y)
#endif

#define RUDP_PACKET_MAX_SIZE 512
#define RUDP_PACKET_HEADER_SIZE 5
#define RUDP_PACKET_FOOTER_SIZE 0
#define RUDP_PACKET_MAX_DATA_SIZE RUDP_PACKET_MAX_SIZE - RUDP_PACKET_HEADER_SIZE - RUDP_PACKET_FOOTER_SIZE

//TODO large data splitting
#define RUDP_DATA 1
#define RUDP_ACK 2
#define RUDP_NACK 3
#define RUDP_RESEND 3


#define RUDP_PACKET_EMPTY 0
#define RUDP_PACKET_NOT_SENT 1
#define RUDP_PACKET_NOT_RECEVED 2
#define RUDP_PACKET_SENT 3
#define RUDP_PACKET_RECEIVED 4
#define RUDP_PACKET_ACK_SENT 5
#define RUDP_PACKET_ACK_RECEIVED 6

#define RUDP_WINDOW_SIZE 10
#define RUDP_WINDOW_BUFFER_SIZE 10
#define RUDP_BUFFER_SIZE 10
#define RUDP_MAX_SESSION_PER_SOCKET 10

#define RUDP_SOCKET_AVAILABLE 0
#define RUDP_SOCKET_ERROR 1
#define RUDP_SOCKET_CLOSED 2

#define RUDP_SESSION_EMPTY 0
#define RUDP_SESSION_NEW 1
#define RUDP_SESSION_ALIVE 2
#define RUDP_SESSION_ERROR 3
#define RUDP_SESSION_CLOSED 4

typedef struct {
    uint16_t frame;
    uint8_t type;
    uint16_t size;
    int8_t data[RUDP_PACKET_MAX_DATA_SIZE];
} rudp_packet;

typedef struct {
    rudp_packet packet;
    uint8_t state;
} rudp_packet_state;

typedef struct {
    int8_t state;
    struct sockaddr_in address;
    uint16_t next_frame_send;
    uint16_t next_frame_recv;
    uint16_t buffer_head;
    rudp_packet_state window_recv[RUDP_WINDOW_BUFFER_SIZE];
    rudp_packet_state window_send[RUDP_WINDOW_BUFFER_SIZE];
    rudp_packet_state buffer[RUDP_BUFFER_SIZE];
} rudp_session;

typedef struct {
    uint8_t state;
    struct sockaddr_in address;
    int socket_handle;
    pthread_t pthread_handle;
    rudp_session sessions[RUDP_MAX_SESSION_PER_SOCKET];
} rudp_socket;

rudp_socket* rudp_bind(const char* address, uint16_t port);

rudp_socket* rudp_create(const char* address, uint16_t port);

int32_t rudp_send(rudp_socket* sock, rudp_session* session, const char* data, uint16_t size);

rudp_session* rudp_accept(rudp_socket* sock);

int32_t rudp_recv(rudp_session* session, char* buffer, uint16_t size);

void rudp_session_close(rudp_session* session);

void rudp_close(rudp_socket* sock);

#endif //RUDP_RUDP_H
