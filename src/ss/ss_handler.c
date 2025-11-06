#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include "ss_file_ops.h"


/**
 * @brief Main router for requests from the NAME SERVER.
 * These are internal, administrative commands.
 */
void handle_nm_request(StorageServerState* state, int nm_sock, MsgHeader* header, MsgPayload* payload) {
    
    safe_printf("SS %u: Received command %u from NM\n", state->ss_id, header->opcode);

    // --- We are MOVING the OP_NM_SS_CREATE_REQ case from here ---

    switch (header->opcode) {
        
        case OP_HEARTBEAT_PING:
            // TODO: Respond with OP_HEARTBEAT_PONG
            break;

        default:
            safe_printf("SS %u: Received unknown opcode %u from NM\n", 
                state->ss_id, header->opcode);
            break;
    }
}


/**
 * @brief Main router for requests from a CLIENT (or NM acting as a client).
 * These are the P1 file operations.
 */
void handle_client_request(StorageServerState* state, int client_sock, MsgHeader* header, MsgPayload* payload) {
    
    safe_printf("SS %u: Received command %u from a client\n", state->ss_id, header->opcode);

    // --- ADD THE LOGIC HERE ---
    switch (header->opcode) {
        
        case OP_NM_SS_CREATE_REQ: { // This is sent by the NM
            MsgHeader res_header = {0};
            MsgPayload res_payload = {0};
            res_header.version = PROTOCOL_VERSION;
            res_header.client_id = state->ss_id; // Identify ourselves
            res_header.error = ERR_NONE;
            res_header.opcode = OP_SS_NM_CREATE_RES;
            res_header.length = sizeof(MsgHeader);

            if (ss_create_file(state, payload->file_req.filename) == -1) {
                safe_printf("SS %u: Failed to create file '%s'\n", 
                    state->ss_id, payload->file_req.filename);
                res_header.error = ERR_UNKNOWN;
            } else {
                safe_printf("SS %u: Successfully created '%s', sending ACK to NM\n", 
                    state->ss_id, payload->file_req.filename);
            }
            
            // Send ACK/NACK back to NM *on this temporary socket*
            if (send_message(client_sock, &res_header, &res_payload) == -1) {
                safe_printf("SS %u: Failed to send CREATE_RES to NM\n", state->ss_id);
            }
            break;
        }
        case OP_CLIENT_SS_READ_REQ: {
            // This function handles the entire read loop and lock release.
            // But it doesn't close the socket.
            handle_ss_read(state, client_sock, &payload->file_req);
            break;
        }
        // TODO: This is where we will handle:
        // OP_CLIENT_SS_READ_REQ
        // OP_CLIENT_SS_WRITE_START
        // OP_CLIENT_SS_STREAM_REQ
        // ...etc

        default:
            safe_printf("SS %u: Received unknown client opcode %u\n",
                state->ss_id, header->opcode);
            break;
    }
    
    // --- END OF ADDED LOGIC ---

    // For now, just close it.
    // The handle_... functions will be responsible for closing
    // in the future.
    close(client_sock);
}