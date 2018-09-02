//
// Created by oryk on 9/1/18.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "rudp.h"

/* Private functions */
/**
 * Compare the two addresses.
 * Checks whether the version of the addresses, ports and actual address.
 *
 * Support for both IPv4 and IPv6.
 *
 * @param first
 * @param second
 * @return
 */
int rudp_cmp_addresses(struct sockaddr_in* first, struct sockaddr_in* second) {
    if (first->sin_family != second->sin_family)
        return 1;
    if (first->sin_family == AF_INET) {
        //IPv4
        if (first->sin_port != second->sin_port) {
            return 1;
        }
        return memcmp(&first->sin_addr, &second->sin_addr, sizeof(struct in_addr));
    } else {
        //IPv6
        struct sockaddr_in6* first6 = (struct sockaddr_in6*) first;
        struct sockaddr_in6* second6 = (struct sockaddr_in6*) second;

        if (first6->sin6_port != second6->sin6_port)
            return 1;
        return memcmp(&first6->sin6_addr, &second6->sin6_addr, sizeof(struct in6_addr));

    }
}

/**
 * Puts the new packet, that just arrived on the network into the session window IF appropriate.
 *
 * When is it NOT appropriate:
 *  1. 'frame' is outside of the window
 *  2. 'frame' has already arrived
 *
 * Either of these cases the packet is discarded.
 *
 * @param session
 * @param packet
 */
void rudp_new_packet(rudp_session* session, rudp_packet* packet) {
    // TODO threadsafe, window frame state?
    // TODO ack if possible
    //No negative check, this is unsigned
    if (packet->frame >= RUDP_WINDOW_SIZE) {
        // TODO statistics
        // TODO is there a way to ask for a resend? We don't know the frame number.
        return;
    }
    if (session->window_recv[packet->frame].state == RUDP_PACKET_EMPTY) {
        memcpy(&session->window_recv[packet->frame].packet, packet, sizeof(*packet));
    }
    // This means, we have the correct packet
    // Check if we can send acknowledgement for more packets.
    // NOTE: When an ACK for a 'later' frame arrives, the protocol assumes, that the previous ones arrived as well
    //
    //  1. Packet2 arrives, no ACK, we need to wait for Packet1
    //  2. Packet1 arrives, send ACK for packet two and slide the window by 2.
    //  3. Sender rececves the ACK for packet two, assumes, packet 1 arrived as well.
    //
    // Maybe to make sure we don't get stuck by acks not arriving, we should send every ack, to increase chances.
    //
    if (packet->frame == session->next_frame_recv) {

    }
}

/* Socket manipulation */
void rudp_set_socket_state(rudp_socket* sock, uint8_t state) {
    //TODO thredsafe
    sock->state = state;
}

bool rudp_is_socket_state(rudp_socket* sock, uint8_t state) {
    //TODO thredsafe
    return sock->state == state;
}

/* Session manipulation */
void rudp_set_session_state(rudp_session* session, uint8_t state) {
    //TODO thredsafe
    session->state = state;
}

bool rudp_is_session_state(rudp_session* session, uint8_t state) {
    //TODO thredsafe
    return session->state == state;
}

/**
 * Initialize a session, if the session is not in use.
 *
 * @param session
 * @param sender
 * @return
 */
bool rudp_initialize_session_if_empty(rudp_session* session, struct sockaddr_in* sender) {
    //TODO thredsafe
    if (session->state != RUDP_SESSION_EMPTY) {
        return false;
    }
    session->state = RUDP_SESSION_ALIVE;
    session->next_frame_send = 0;
    session->next_frame_recv = 0;
    //TODO IPv6
    memcpy(&session->address, &sender, sizeof(struct sockaddr_in));
    memset(session->buffer, 0, sizeof(session->buffer));
    memset(session->window_send, 0, sizeof(session->window_send));
    memset(session->window_recv, 0, sizeof(session->window_recv));
    return true;
}


void* receiver_thread(void* ptr) {
    rudp_socket* sock = (rudp_socket*) ptr;
    //TODO IPv6
    struct sockaddr_in sender;
    socklen_t socklen;
    rudp_packet packet;
    int32_t recv;
    bool new_session;

    while (rudp_is_socket_state(sock, RUDP_SOCKET_AVAILABLE)) {
        new_session = true;
        /** From docs:
         * All three routines return the length of the message on successful completion. If a message is too long
         * to fit in the supplied buffer, excess bytes may be discarded depending on the type of socket the message
         * is received from.
         */
        recv = (int32_t) recvfrom(
                sock->socket_handle,
                (void*) &packet,
                RUDP_PACKET_MAX_SIZE,
                0,
                (struct sockaddr*) &sender,
                &socklen
        );
        if (recv < 0) {
            rudp_set_socket_state(sock, RUDP_SOCKET_ERROR);
            continue;
        }
        // Look for the ip in the session list
        // TODO replace this with some kind of session id
        for (int i = 0; i < RUDP_MAX_SESSION_PER_SOCKET; ++i) {
            if (rudp_is_session_state(&sock->sessions[i], RUDP_SESSION_ALIVE) &&
                rudp_cmp_addresses(&sock->sessions[i].address, &sender)) {
                rudp_new_packet(&sock->sessions[i], &packet);
                new_session = false;
                break;
            }
        }
        if (new_session) {
            // TODO optimize, try to avoid full iteration every time
            for (int i = 0; i < RUDP_MAX_SESSION_PER_SOCKET; ++i) {
                if (rudp_initialize_session_if_empty(&sock->sessions[i], &sender)) {
                    rudp_new_packet(&sock->sessions[i], &packet);
                    break;
                }
            }
        }

    }

    return NULL;
}

rudp_socket* alloc_socket() {
    rudp_socket* sock = malloc(sizeof(*sock));
    if (sock == NULL)
        return NULL;
    memset(sock, 0, sizeof(*sock));
    return sock;
}

void free_socket(rudp_socket* sock) {
    if (sock != NULL)
        free(sock);
}

/* Interface implementations */

rudp_socket* rudp_bind(const char* address, uint16_t port) {
    rudp_socket* sock = rudp_create(address, port);
    if (bind(sock->socket_handle, (struct sockaddr*) &sock->address, sizeof(sock->address)) == -1) {
        sock->state = RUDP_SOCKET_ERROR;
        perror("Failed to bind socket");
        rudp_close(sock);
        return NULL;
    }
    return sock;

}

rudp_socket* rudp_create(const char* address, uint16_t port) {
    rudp_socket* sock = alloc_socket();
    if (sock == NULL) {
        fprintf(stderr, "Failed to allocate memory for the socket.\n");
        free_socket(sock);
        return NULL;
    }
    if ((sock->socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "Failed to create socket.\n");
        free_socket(sock);
        return NULL;
    }

    sock->address.sin_family = AF_INET;
    sock->address.sin_port = htons(port);

    if (inet_aton(address, &sock->address.sin_addr) == 0) {
        fprintf(stderr, "Address is in wrong format\n");
        rudp_close(sock);
        return NULL;
    }


    if (pthread_create(&sock->pthread_handle, NULL, receiver_thread, (void*) sock)) {
        perror("Failed to create receiver thread");
        rudp_close(sock);
        return NULL;
    }
    // This is set by the memset and also the 'session.state' is initialized this way.
//    sock->state = RUDP_SOCKET_AVAILABLE;


    return sock;

}

int32_t rudp_send(rudp_socket* sock, rudp_session* session, const char* data, uint16_t size) {
    rudp_packet_state* state = NULL;
    uint16_t sliding = 0;
    for (int i = 0; i < RUDP_WINDOW_SIZE; ++i) {
        sliding = (uint16_t) ((i + session->next_frame_send) % RUDP_WINDOW_SIZE);
        if (session->window_send[sliding].state == RUDP_PACKET_EMPTY) {
            state = &session->window_send[sliding];
            break;
        }
    }
    if (state == NULL) {
        return -1;
    }
    //TODO if size is bigger than the max, create separate frames
    state->state = RUDP_PACKET_NOT_SENT;
    state->packet.size = size;
    state->packet.frame = sliding;
    memcpy(state->packet.data, data, size);


    int32_t sent_bytes = (int32_t) sendto(
            sock->socket_handle,
            data,
            size,
            0,
            (struct sockaddr*) &session->address,
            sizeof(session->address)
    );
    //TODO what if can't send message.
    if (sent_bytes == -1) {
        return -1;
    }
    state->state = RUDP_PACKET_SENT;
    return sent_bytes;
}

rudp_session* rudp_receive(rudp_socket* sock, char* data, uint16_t size) {
    struct sockaddr_in sender;
    socklen_t socklen;
    int32_t recv = (int32_t) recvfrom(
            sock->socket_handle,
            data,
            size,
            0,
            (struct sockaddr*) &sender,
            &socklen
    );
    if (recv == -1) {
        return NULL;
    }
    return session;
    //print details of the client/peer and the data received
//    printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
//    printf("Data: %s\n", buf);
}

void rudp_close(rudp_socket* sock) {
    sock->state = RUDP_SOCKET_CLOSED;
    close(sock->socket_handle);
    //TODO wait for the thread to finish for a LIMITED time
    pthread_join(sock->pthread_handle, NULL);
    free_socket(sock);
}

