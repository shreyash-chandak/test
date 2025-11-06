#ifndef NM_REQUEST_HELPERS_H
#define NM_REQUEST_HELPERS_H

#include "protocol.h"
#include "nm_structs.h"

/**
 * @brief Handles a client's OP_CLIENT_LIST_REQ.
 * Iterates the user map, builds a response, and sends it.
 */
void handle_list(uint32_t client_id, int sock, MsgHeader* header, NameServerState* state);

void handle_create(uint32_t client_id, int sock, MsgHeader* header, 
                   Payload_FileRequest* payload, NameServerState* state);

/**
 * @brief Handles P1 redirect commands (READ, WRITE, STREAM, UNDO).
 * Finds the correct SS and sends a redirect packet to the client.
 */
void handle_redirect(uint32_t client_id, int sock, MsgHeader* header, 
                     Payload_FileRequest* payload, NameServerState* state);

void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_FileRequest* payload, NameServerState* state);

#endif // NM_REQUEST_HELPERS_H