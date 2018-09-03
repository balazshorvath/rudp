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
#include <signal.h>

#include "rudp.h"

/* Private functions */

bool rudp_session_buffer_push(rudp_session* session, rudp_packet_state* packet_state) {
    //TODO threadsafe
    SLIDING_FOR(session->buffer_head, RUDP_BUFFER_SIZE, RUDP_BUFFER_SIZE) {
        printf("rudp_session_buffer_push %d", sliding);
        if (session->buffer[sliding].state == RUDP_PACKET_EMPTY) {
            memcpy(&session->buffer[sliding], packet_state, sizeof(rudp_packet_state));
//            session->buffer[sliding].state = RUDP_PACKET_ACK_SENT;
            return true;
        }
    }
    return false;
}

/**
 * Sends an acknowledgement message for the specified packet.
 *
 * @param sock
 * @param session
 * @param packet
 * @return
 */
int32_t rudp_send_ack(rudp_socket* sock, rudp_session* session, rudp_packet_state* packet) {
    rudp_packet ack = {.frame = packet->packet.frame, .type = RUDP_ACK, .size = 0};
    int32_t sent_bytes = (int32_t) sendto(
            sock->socket_handle,
            (void*) &ack,
            RUDP_PACKET_HEADER_SIZE,
            0,
            (struct sockaddr*) &session->address,
            sizeof(session->address)
    );
    if (sent_bytes == -1) {
        perror("Failed to send ack message");
        return -1;
    }
    packet->state = RUDP_PACKET_ACK_SENT;
    return sent_bytes;
}

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
void rudp_new_packet(rudp_socket* sock, rudp_session* session, rudp_packet* packet) {
    // TODO threadsafe, window frame state?
    // TODO ack if possible
    //No negative check, this is unsigned
    if (session->next_frame_recv >= packet->frame || packet->frame >= session->next_frame_recv + RUDP_WINDOW_SIZE) {
        // TODO statistics
        // TODO is there a way to ask for a resend? We don't know the frame number. Assume the number is actually corrupt.
        return;
    }
    if (session->window_recv[packet->frame].state == RUDP_PACKET_EMPTY) {
        memcpy(&session->window_recv[packet->frame].packet, packet, sizeof(rudp_packet));
        session->window_recv[packet->frame].state = RUDP_PACKET_RECEIVED;
    } else {
        // TODO statistics
        return;
    }
    // This means, we have the correct packet
    // Check if we can send acknowledgement for more packets.
    // NOTE: When an ACK for a 'later' frame arrives, the protocol assumes, that the previous ones arrived as well
    //
    //  1. Packet2 arrives, no ACK, we need to wait for Packet1
    //  2. Packet1 arrives, send ACK for packet two and slide the window by 2.
    //  3. Sender receives the ACK for packet two, assumes, packet 1 arrived as well.
    //
    // Maybe to make sure we don't get stuck by acks not arriving, we should send every ack, to increase chances.
    //
    uint16_t sliding;
    for (int i = 0; i < RUDP_WINDOW_SIZE; ++i) {
        sliding = (uint16_t) ((i + session->next_frame_send) % RUDP_WINDOW_BUFFER_SIZE);
        // Go until we have messages waiting to be responded to.
        //
        if (session->window_recv[sliding].state == RUDP_PACKET_RECEIVED) {
            //Send ack
            rudp_send_ack(sock, session, &session->window_recv[sliding]);

            if (session->window_recv[sliding].state == RUDP_PACKET_ACK_SENT) {
                //TODO multi-packet messages should still be a thing.
                //TODO what if this fails?
                rudp_session_buffer_push(session, &session->window_recv[sliding]);
                INCREMENT_SLIDING(session->next_frame_recv, RUDP_WINDOW_BUFFER_SIZE);

            } else {
                //TODO statistics
                //TODO retry
            }
        } else {
            break;
        }
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

bool rudp_set_session_state_if(rudp_session* session, uint8_t expected, uint8_t new_state) {
    //TODO thredsafe
    if (session->state == expected) {
        session->state = new_state;
        return true;
    }
    return false;
}

/**
 * Initialize a session, if the session is not in use.
 *
 * Session lifecycle:
 *  1. EMPTY-> initial state
 *  2. NEW-> rudp_initialize_session_if_empty() is called
 *  3. ALIVE-> rudp_accept() is called and this session is returned
 *  4. CLOSED/ERROR-> somethis bad happens, ot the session is closed
 *
 * @param session
 * @param sender
 * @return
 */
bool rudp_initialize_session_if_empty(rudp_session* session, struct sockaddr_in* sender) {
    //TODO thredsafe
    if (!rudp_set_session_state_if(session, RUDP_SESSION_EMPTY, RUDP_SESSION_NEW)) {
        return false;
    }
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
        //TODO use 'select' for timeout
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
                rudp_new_packet(sock, &sock->sessions[i], &packet);
                new_session = false;
                break;
            }
        }
        if (new_session) {
            // TODO optimize, try to avoid full iteration every time
            for (int i = 0; i < RUDP_MAX_SESSION_PER_SOCKET; ++i) {
                if (rudp_initialize_session_if_empty(&sock->sessions[i], &sender)) {
                    rudp_new_packet(sock, &sock->sessions[i], &packet);
                    new_session = false;
                    break;
                }
            }
            if (new_session) {
                //TODO respond with no slots left.
                fprintf(stderr, "There isn't enough session slots left.\n");
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
    //TODO threadsafe
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
        perror("Failed to create socket");
        free_socket(sock);
        return NULL;
    }

    sock->address.sin_family = AF_INET;
    sock->address.sin_port = htons(port);

    if (inet_aton(address, &sock->address.sin_addr) == 0) {
        perror("Error while converting address");
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
        sliding = (uint16_t) ((i + session->next_frame_send) % RUDP_WINDOW_BUFFER_SIZE);
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
        perror("Could not send message");
        return -1;
    }
    state->state = RUDP_PACKET_SENT;
    return sent_bytes;
}

/**
 * Returns with a session, if there is one with RUDP_SESSION_NEW state.
 * Also sets the state to ALIVE, meaning, that the session has been recognized by the application and is being used.
 *
 * @param sock
 * @return
 */
rudp_session* rudp_accept(rudp_socket* sock) {
    //TODO lock on socket
    for (int i = 0; i < RUDP_MAX_SESSION_PER_SOCKET; ++i) {
        if (rudp_set_session_state_if(&sock->sessions[i], RUDP_SESSION_NEW, RUDP_SESSION_ALIVE)) {
            return &sock->sessions[i];
        }
    }
    return NULL;
}

/**
 * If a session got into an error state, the session can be freed with this call.
 *
 * @param session
 */
void rudp_session_close(rudp_session* session) {
    rudp_set_session_state(session, RUDP_SESSION_EMPTY);
}

/**
 * If the buffer is too small for the amount of data in the packet, the rest of the data will be lost.
 *
 * @param session
 * @param data
 * @param size
 * @return
 */
int32_t rudp_recv(rudp_session* session, char* data, uint16_t size) {
    //TODO lock on session
    if (session->buffer[session->buffer_head].state != RUDP_PACKET_EMPTY) {
        session->buffer[session->buffer_head].state = RUDP_PACKET_EMPTY;
        uint16_t actual_size = MAX(session->buffer[session->buffer_head].packet.size, size);
        memcpy(
                data,
                session->buffer[session->buffer_head].packet.data,
                actual_size
        );
        INCREMENT_SLIDING(session->buffer_head, RUDP_BUFFER_SIZE);
        return actual_size;
    }
    return -1;
}

void rudp_close(rudp_socket* sock) {
    sock->state = RUDP_SOCKET_CLOSED;
    close(sock->socket_handle);
    //TODO wait for the thread to finish for a LIMITED time
    pthread_join(sock->pthread_handle, NULL);
    free_socket(sock);
}

