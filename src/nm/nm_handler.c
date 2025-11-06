#include "nm_handler.h"
#include "protocol.h"
#include "utils.h"
#include "nm_structs.h"
#include "common.h"
#include "nm_state.h" // <-- Ensures we have the new function prototypes
#include "nm_request_helpers.h"

void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_FileRequest* payload, NameServerState* state);

void* handle_connection(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    int sock = args->socket_fd;
    NameServerState* state = args->state;
    free(arg); 

    MsgHeader header;
    MsgPayload payload;
    uint32_t id = 0; 
    
    if (recv_message(sock, &header, &payload) <= 0) {
        safe_printf("NM: Connection %d disconnected before registration.\n", sock);
        close(sock);
        return NULL;
    }

    safe_printf("NM: Connection %d sent opcode %u as first message.\n", sock, header.opcode);

    // 2. --- Route to the correct registration handler ---
    switch (header.opcode) {
        case OP_CLIENT_REGISTER_REQ: {
            // --- Declare all response/error variables at the top ---
            MsgHeader res_header = {0};
            MsgPayload res_payload = {0};
            ErrorCode err_code = ERR_NONE; // This will be an [out] parameter

            // --- CRITICAL FIX: Sanitize input strings ---
            payload.client_reg_req.username[MAX_USERNAME_LEN - 1] = '\0';
            payload.client_reg_req.password[MAX_PASSWORD_LEN - 1] = '\0';
            payload.client_reg_req.username[strcspn(payload.client_reg_req.username, "\r\n")] = 0;
            payload.client_reg_req.password[strcspn(payload.client_reg_req.password, "\r\n")] = 0;
            
            // --- UPDATED CALL: Pass the err_code pointer ---
            id = register_client(sock, &payload.client_reg_req, state, &err_code);
            
            if (id == 0) {
                // --- FAILURE PATH: Send specific error ---
                safe_printf("NM: Client registration failed for socket %d (Error: %d).\n", sock, err_code);
                
                res_header.version = PROTOCOL_VERSION;
                res_header.opcode = OP_ERROR_RES; // Generic error response
                res_header.error = err_code;      // The specific error
                res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
                
                if (err_code == ERR_ACCESS_DENIED) {
                    strncpy(res_payload.error.message, "Invalid username or password.", MAX_ERROR_MSG_LEN - 1);
                }
                else if (err_code == ERR_ALREADY_ACTIVE) {
                    strncpy(res_payload.error.message, "User already active elsewhere.", MAX_ERROR_MSG_LEN - 1);
                } else {
                    strncpy(res_payload.error.message, "Registration/Login failed.", MAX_ERROR_MSG_LEN - 1);
                }
                
                send_message(sock, &res_header, &res_payload);
                close(sock);
                return NULL;
            }

            // --- SUCCESS PATH: Send "OK" Response ---
            res_header.version = PROTOCOL_VERSION;
            res_header.opcode = OP_CLIENT_REGISTER_RES;
            res_header.client_id = id;
            res_header.error = ERR_NONE;
            res_header.length = sizeof(MsgHeader) + sizeof(Payload_ClientRegisterRes);
            res_payload.client_reg_res.new_client_id = id;
            
            if (send_message(sock, &res_header, &res_payload) == -1) {
                safe_printf("NM: Failed to send registration response to client.\n");
                handle_disconnect(sock, state);
                return NULL;
            }
            break;
        }
        
        case OP_SS_REGISTER_REQ: {
            // --- SS Registration ---
            MsgHeader res_header = {0}; // Local to this case

            // We should update register_ss to also use ErrorCode,
            // but for now, we'll keep the old logic.
            id = register_ss(sock, &payload.ss_reg_req, state);
            if (id == 0) {
                safe_printf("NM: SS registration failed for socket %d.\n", sock);
                // TODO: Send OP_ERROR_RES
                close(sock);
                return NULL;
            }

            res_header.version = PROTOCOL_VERSION;
            res_header.opcode = OP_SS_REGISTER_RES;
            res_header.client_id = id;
            res_header.error = ERR_NONE;
            res_header.length = sizeof(MsgHeader); // No payload
            
            if (send_message(sock, &res_header, NULL) == -1) {
                safe_printf("NM: Failed to send registration response to SS.\n");
                handle_disconnect(sock, state);
                return NULL;
            }
            break;
        }
        
        default:
            safe_printf("NM: Connection %d sent invalid first opcode %u. Closing.\n", sock, header.opcode);
            // TODO: Send OP_ERROR_RES
            close(sock);
            return NULL;
    }
    
    // 3. --- If registration was successful, enter the main request loop ---
    safe_printf("NM: Connection %d successfully registered. Entering main loop.\n", sock);

    // This `id` is the client_id or ss_id
    bool is_client = (header.opcode == OP_CLIENT_REGISTER_REQ);

    while (recv_message(sock, &header, &payload) > 0) {

        // --- THIS IS THE NEW ROUTER ---
        if (is_client) {
            // Set the client_id on the header so we know who is asking
            header.client_id = id; 
            route_client_request(id, sock, &header, &payload, state);
        } else {
            // Set the ss_id on the header (in the client_id field)
            header.client_id = id;
            route_ss_request(id, sock, &header, &payload, state);
        }
        // -----------------------------

        if (header.opcode == OP_DISCONNECT_REQ) {
            break;
        }
    }

    // 4. --- Handle disconnect ---
    safe_printf("NM: ID %u on socket %d disconnected.\n", id, sock);
    handle_disconnect(sock, state);
    return NULL;
}

// --- ADD THESE NEW (EMPTY) FUNCTIONS TO nm_handler.c ---
// We will build these out, one opcode at a time.

/**
 * @brief Main router for all opcodes from a registered CLIENT.
 */
void route_client_request(uint32_t client_id, int sock, MsgHeader* header, 
                          MsgPayload* payload, NameServerState* state) {

    safe_printf("NM: Routing CLIENT opcode %u from client %u\n", header->opcode, client_id);

    switch (header->opcode) {
        // --- P2: NM-Handled Features ---
        case OP_CLIENT_VIEW_REQ:
            // TODO: handle_view(client_id, sock, header, &payload->client_view_req, state);
            break;
        case OP_CLIENT_CREATE_REQ:
            handle_create(client_id, sock, header, &payload->file_req, state);
            break;
        case OP_CLIENT_DELETE_REQ:
            // TODO: handle_delete(client_id, sock, header, &payload->file_req, state);
            break;
        case OP_CLIENT_INFO_REQ:
            // TODO: handle_info(client_id, sock, header, &payload->file_req, state);
            break;
        case OP_CLIENT_LIST_REQ:
            handle_list(client_id, sock, header, state);
            break;
        case OP_CLIENT_ACCESS_REQ:
            // TODO: handle_access(client_id, sock, header, &payload->access_req, state);
            break;

        // --- P1: 3-Way Handshake Triggers ---
        case OP_CLIENT_READ_REQ:
        case OP_CLIENT_WRITE_REQ:
        case OP_CLIENT_STREAM_REQ:
        case OP_CLIENT_UNDO_REQ:
            handle_redirect(client_id, sock, header, &payload->file_req, state);
            break;

        // --- P2: Exec ---
        case OP_CLIENT_EXEC_REQ:
            // TODO: handle_exec(client_id, sock, header, &payload->file_req, state);
            break;

        case OP_HEARTBEAT_PONG:
            // TODO: handle_client_pong(client_id, state);
            break;

        default:
            safe_printf("NM: Unknown opcode %u from client %u. Ignoring.\n", header->opcode, client_id);
            // TODO: Send ERR_INVALID_COMMAND
            break;
    }
}

/**
 * @brief Main router for all opcodes from a registered SS.
 */
void route_ss_request(uint32_t ss_id, int sock, MsgHeader* header, 
                      MsgPayload* payload, NameServerState* state) {

    safe_printf("NM: Routing SS opcode %u from SS %u\n", header->opcode, ss_id);

    switch(header->opcode) {
        case OP_SS_SYNC_FILE_INFO:
            handle_ss_sync_file(ss_id, header, &payload->file_req, state);
            break;
        case OP_HEARTBEAT_PONG:
            // TODO: handle_ss_pong(ss_id, state);
            break;

        // --- Responses to NM-issued commands ---
        case OP_SS_NM_INTERNAL_READ_RES:
            // TODO: handle_exec_ss_response(ss_id, sock, header, &payload->file_chunk, state);
            break;

        default:
             safe_printf("NM: Unknown opcode %u from SS %u. Ignoring.\n", header->opcode, ss_id);
             break;
    }
}