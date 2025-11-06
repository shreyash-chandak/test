#ifndef NM_HANDLER_H
#define NM_HANDLER_H

#include "nm_structs.h"

// We move this here so nm_main.c can see it
typedef struct {
    int socket_fd;
    NameServerState* state;
} ThreadArgs;

/**
 * @brief The main thread routine for every new connection.
 * This is the function `pthread_create` calls.
 * It will handle the initial registration and then loop
 * for all subsequent requests.
 */
void* handle_connection(void* arg);

void route_client_request(uint32_t client_id, int sock, MsgHeader* header, 
                          MsgPayload* payload, NameServerState* state);

void route_ss_request(uint32_t ss_id, int sock, MsgHeader* header, 
                      MsgPayload* payload, NameServerState* state);

#endif // NM_HANDLER_H
