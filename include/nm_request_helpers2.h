#ifndef NM_REQUEST_HELPERS2_H
#define NM_REQUEST_HELPERS2_H

#include "protocol.h"
#include "nm_structs.h"

/**
 * @brief Handles a client's OP_CLIENT_LIST_REQ.
 * Iterates the user map, builds a response, and sends it.
 */
void handle_list(uint32_t client_id, int sock, MsgHeader* header, NameServerState* state);

void handle_info(uint32_t client_id, int sock, 
                 Payload_FileRequest* payload, NameServerState* state);


void handle_view(uint32_t client_id, int sock, 
                        Payload_ClientViewReq* payload, NameServerState* state);

void handle_ss_write_complete(uint32_t ss_id, Payload_SSNMWriteComplete* payload, NameServerState* state);

void handle_exec(uint32_t client_id, int sock, Payload_FileRequest* payload, NameServerState* state);

void handle_ss_undo_complete(uint32_t ss_id, Payload_SSNMUndoComplete* payload, 
                             NameServerState* state);

void handle_ss_redo_complete(uint32_t ss_id, Payload_SSNMRedoComplete* payload, 
                             NameServerState* state);

void handle_ss_revert_complete(uint32_t ss_id, Payload_SSNMRevertComplete* payload, 
                               NameServerState* state);

#endif // NM_REQUEST_HELPERS2_H