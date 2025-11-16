#ifndef SS_HANDLER_H
#define SS_HANDLER_H

#include "ss_structs.h"

/**
 * @brief Main router for requests from the NAME SERVER.
 * This runs in the 'run_nm_client' thread.
 */
void handle_nm_request(StorageServerState* state, int nm_sock, MsgHeader* header, MsgPayload* payload);

/**
 * @brief The main thread routine for every new CLIENT connection.
 * This is the function `pthread_create` calls.
 * It handles the entire stateful session (e.g., READ, or WRITE loop).
 */
void* handle_client_connection(void* arg);

#endif // SS_HANDLER_H