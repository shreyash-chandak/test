#ifndef NM_REQUEST_HELPERS_H
#define NM_REQUEST_HELPERS_H

#include "protocol.h"
#include "nm_structs.h"

/**
 * @brief Handles a client's OP_CLIENT_LIST_REQ.
 * Iterates the user map, builds a response, and sends it.
 */

void handle_create(uint32_t client_id, int sock, MsgHeader* header, 
                   Payload_FileRequest* payload, NameServerState* state);


void handle_delete(uint32_t client_id, int sock, 
                          Payload_FileRequest* payload, NameServerState* state);

// Handles P1 redirect commands (READ, WRITE, STREAM, UNDO)

void handle_redirect(uint32_t client_id, int sock, MsgHeader* header, 
                     Payload_FileRequest* payload, NameServerState* state);

void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_SSSyncFile* payload, NameServerState* state);

#endif // NM_REQUEST_HELPERS_H