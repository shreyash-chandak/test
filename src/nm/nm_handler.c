#include "nm_handler.h"
#include "protocol.h"
#include "utils.h"
#include "nm_structs.h"
#include "common.h"
#include "nm_state.h"
#include "nm_request_helpers.h"
#include "nm_request_helpers2.h"
#include "nm_persistence.h"
#include "nm_access.h"
#include "lru_cache.h" 

/**
 * @brief Gets file metadata, using the LRU cache.
 * Fetches from main map and populates cache on miss.
 */
static FileMetadata* get_metadata_with_cache(NameServerState* state, const char* filename) {
    // 1. Check cache first
    FileMetadata* meta = (FileMetadata*)lru_cache_get(state->file_cache, filename);
    
    if (meta == NULL) {
        // 2. Cache miss: Get from main map
        meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, filename);
        
        if (meta != NULL) {
            // 3. Found in main map: Add to cache
            lru_cache_put(state->file_cache, filename, meta);
        }
    }
    // 'meta' is either the cached/found pointer, or NULL
    return meta;
}

void* handle_connection(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    int sock = args->socket_fd;
    NameServerState* state = args->state;
    free(arg); 

    MsgHeader header;
    MsgPayload payload;
    uint32_t id = 0; 
    
    // --- Get Peer Info for Logging ---
    char client_ip[INET_ADDRSTRLEN];
    uint16_t client_port;
    get_peer_info(sock, client_ip, sizeof(client_ip), &client_port);

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

            // --- Sanitize input strings ---
            payload.client_reg_req.username[MAX_USERNAME_LEN - 1] = '\0';
            payload.client_reg_req.password[MAX_PASSWORD_LEN - 1] = '\0';
            payload.client_reg_req.username[strcspn(payload.client_reg_req.username, "\r\n")] = 0;
            payload.client_reg_req.password[strcspn(payload.client_reg_req.password, "\r\n")] = 0;

            safe_printf("NM: Registering Client [%s:%u] as '%s'...\n", 
                        client_ip, client_port, payload.client_reg_req.username);
            
            // --- Pass the err_code pointer ---
            id = register_client(sock, &payload.client_reg_req, state, &err_code);
            
            if (id == 0) {
                // --- Send specific error ---
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
            close(sock);
            return NULL;
    }
    
    // 3. --- If registration was successful, enter the main request loop ---
    safe_printf("NM: Session established with ID %u (%s:%u).\n", id, client_ip, client_port);

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
    safe_printf("NM: ID %u (%s:%u) disconnected.\n", id, client_ip, client_port);
    handle_disconnect(sock, state);
    return NULL;
}

/**
 * @brief Main router for all opcodes from a registered CLIENT.
 */
void route_client_request(uint32_t client_id, int sock, MsgHeader* header, 
                          MsgPayload* payload, NameServerState* state) {

    const char* username = get_username_from_id(state, client_id);
    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    get_peer_info(sock, ip, sizeof(ip), &port);

    safe_printf("NM: REQ from User '%s' (ID %u) [%s:%u] -> OpCode %u\n", 
                username ? username : "Unknown", client_id, ip, port, header->opcode);

    switch (header->opcode) {
        // --- P2: NM-Handled Features ---
        case OP_CLIENT_VIEW_REQ:
            handle_view(client_id, sock, &payload->client_view_req, state);
        break;
            
        case OP_CLIENT_CREATE_REQ:
            handle_create(client_id, sock, header, &payload->file_req, state);
            break;
        case OP_CLIENT_DELETE_REQ:{ 
            
            // 1. Get the payload
            Payload_FileRequest* req = &payload->file_req; 

            // 2. Get parameters: meta and username
            FileMetadata* meta = get_metadata_with_cache(state, req->filename);
            const char* username = get_username_from_id(state, client_id);

            // 3. Check for NULLs
            if (meta == NULL) {
                send_nm_error(sock, ERR_FILE_NOT_FOUND, "File not found.");
                break;
            }
            if (username == NULL) {
                send_nm_error(sock, ERR_UNKNOWN, "Internal server error: Client session not found.");
                break;
            }
            if (strcmp(username, meta->owner_username) != 0) {
                send_nm_error(sock, ERR_ACCESS_DENIED, "Access denied: Only the file owner can delete this file.");
                break;
            }

            // If check passes, proceed to the original handler
            handle_delete(client_id, sock, &payload->file_req, state);
            break;
        }
        case OP_CLIENT_INFO_REQ:{
            
            Payload_FileRequest* req = &payload->file_req;

            // 2. Get parameters: meta and username
            FileMetadata* meta = get_metadata_with_cache(state, req->filename);
            const char* username = get_username_from_id(state, client_id);

            // 3. Check for NULLs
            if (meta == NULL) {
                send_nm_error(sock, ERR_FILE_NOT_FOUND, "File not found.");
                break;
            }
            if (username == NULL) {
                send_nm_error(sock, ERR_UNKNOWN, "Internal server error: Client session not found.");
                break;
            }

            // 4. Get parameters: required_level (INFO needs READ)
            PermissionLevel required_perm = PERM_READ;

            // 5. Call the check
            if (!check_access(meta, username, required_perm)) {
                send_nm_error(sock, ERR_ACCESS_DENIED, "Access denied: You do not have permission to view this file.");
                break;
            }
            
            handle_info(client_id, sock, &payload->file_req, state);
            break;
        }

        case OP_CLIENT_LIST_REQ:
            handle_list(client_id, sock, header, state);
            break;

        case OP_CLIENT_ACCESS_REQ: {
            Payload_ClientAccessReq* req = &payload->access_req; 
            MsgHeader res_header = {0};

            // --- Prepare Response Header ---
            res_header.version = PROTOCOL_VERSION;
            res_header.opcode = OP_NM_ACCESS_RES; 
            res_header.length = sizeof(MsgHeader); 
            res_header.error = ERR_NONE;

            // 1. Get the file's metadata
            FileMetadata* meta = get_metadata_with_cache(state, req->filename);

            if (meta == NULL) {
                send_nm_error(sock, ERR_FILE_NOT_FOUND, "File not found.");
                break;
            }

            // 2. Permission Check: Get client's username
            
            const char* client_username = get_username_from_id(state, client_id);

            if (client_username == NULL) {
                send_nm_error(sock, ERR_UNKNOWN, "Internal server error: Client ID not found.");
                break;
            }
            
            // Only the owner can change permissions 
            if (strcmp(client_username, meta->owner_username) != 0) {
                send_nm_error(sock, ERR_ACCESS_DENIED, "Access denied: Only the file owner can change permissions.");
                break;
            }
            if (ts_hashmap_get(state->client_username_map, req->username) == NULL) { 
                send_nm_error(sock, ERR_USER_NOT_FOUND, "User not found: The specified user does not exist.");
                break;
            }
            if(req->flags & ACCESS_FLAG_REMOVE && (strcmp(req->username, meta->owner_username) == 0)) {
                send_nm_error(sock, ERR_INVALID_COMMAND, "Invalid operation.\nLMAO cope harder. you cannot kick yourself out of the file.");
                break;
            }
            if (strcmp(req->username, meta->owner_username) == 0) {
                send_nm_error(sock, ERR_INVALID_COMMAND, "Cannot modify the owner's access permissions.");
                break;
            }

            // 3. Lock the file's metadata to safely modify its ACL
            pthread_mutex_lock(&meta->meta_lock);

            if (req->flags & (ACCESS_FLAG_READ_ADD | ACCESS_FLAG_WRITE_ADD)) { 
                // --- ADD/UPDATE Access ---
                const char* level = (req->flags & ACCESS_FLAG_WRITE_ADD) ? "RW" : "R";
                char* level_str_alloc = strdup(level);
                if (!level_str_alloc) {
                    res_header.error = ERR_UNKNOWN; // Out of memory
                } else {
                    // Log the change
                    persistence_log_op("META,ADDACCESS,%s,%s,%s\n", 
                                       req->filename, req->username, level); 
                    
                    // Remove old permission string to prevent leak
                    void* old_level = ts_hashmap_remove(meta->access_list, req->username); 
                    if (old_level) {
                        free(old_level);
                    }
                    
                    // Add the new permission
                    ts_hashmap_put(meta->access_list, req->username, (void*)level_str_alloc); 
                }

            } else if (req->flags & ACCESS_FLAG_REMOVE) { 
                // --- REMOVE Access ---
                persistence_log_op("META,REMACCESS,%s,%s\n", 
                                   req->filename, req->username); 
                
                // Remove the permission and free the string
                void* old_level = ts_hashmap_remove(meta->access_list, req->username); 
                if (old_level) {
                    free(old_level);
                }
            }

            // 4. Unlock the file's metadata
            pthread_mutex_unlock(&meta->meta_lock);

            // 5. Send final response (success or error)
            send_message(sock, &res_header, NULL); 
            break;
        }

        case OP_CLIENT_REQACCESS_REQ:
            handle_reqaccess(client_id, sock, &payload->file_req, state);
            break;
        case OP_CLIENT_LISTREQS_REQ:
            handle_listreqs(client_id, sock, &payload->file_req, state);
            break;
        case OP_CLIENT_APPROVE_REQ:
            handle_approve(client_id, sock, &payload->access_req, state);
            break;

        // --- P1: 3-Way Handshake Triggers ---
        case OP_CLIENT_READ_REQ:
        case OP_CLIENT_WRITE_REQ:
        case OP_CLIENT_STREAM_REQ:
        case OP_CLIENT_UNDO_REQ: 
        case OP_CLIENT_REDO_REQ:
        case OP_CLIENT_CHECKPOINT_REQ:
        case OP_CLIENT_REVERT_REQ:
        case OP_CLIENT_VIEWCHECKPOINT_REQ:
        case OP_CLIENT_LISTCHECKPOINTS_REQ: {

            Payload_FileRequest* req;
            if (header->opcode == OP_CLIENT_CHECKPOINT_REQ || header->opcode == OP_CLIENT_REVERT_REQ || header->opcode == OP_CLIENT_VIEWCHECKPOINT_REQ) {
                // These commands use the *new* payload struct
                req = (Payload_FileRequest*)&payload->checkpoint_req; 
            } else {
                // These commands use the original payload struct
                req = &payload->file_req;
            }

            // 2. Get parameters: meta and username
            FileMetadata* meta = get_metadata_with_cache(state, req->filename); 
            const char* username = get_username_from_id(state, client_id);

            // 3. Check for NULLs
            if (meta == NULL) {
                send_nm_error(sock, ERR_FILE_NOT_FOUND, "File not found.");
                break;
            }
            if (username == NULL) {
                send_nm_error(sock, ERR_UNKNOWN, "Internal server error: Client session not found.");
                break;
            }

            // 4. Get parameters: required_level and err_msg
            PermissionLevel required_perm;
            const char* err_msg;
            bool is_write_op = (header->opcode == OP_CLIENT_WRITE_REQ || 
                                header->opcode == OP_CLIENT_UNDO_REQ || 
                                header->opcode == OP_CLIENT_REDO_REQ ||
                                header->opcode == OP_CLIENT_CHECKPOINT_REQ ||
                                header->opcode == OP_CLIENT_REVERT_REQ);

            if (is_write_op) {
                required_perm = PERM_WRITE;
                err_msg = "Access denied: You do not have permission to write to this file.";
            } else {
                required_perm = PERM_READ;
                err_msg = "Access denied: You do not have permission to read this file.";
            }

            // 5. Call the check
            if (!check_access(meta, username, required_perm)) {
                send_nm_error(sock, ERR_ACCESS_DENIED, err_msg);
                break;
            }
            
            handle_redirect(client_id, sock, header, &payload->file_req, state);
            break;
        }
        // --- P2: Exec ---
        case OP_CLIENT_EXEC_REQ:
            //safe_printf("DEBUG (NM): Received OP_CLIENT_EXEC_REQ for %s from client %u\n", payload->file_req.filename, client_id);
            handle_exec(client_id, sock, &payload->file_req, state);
            break;

        case OP_HEARTBEAT_PONG:
            // TODO: handle_client_pong(client_id, state);
            break;

        default:
            safe_printf("NM: Unknown opcode %u from client %u.\n", header->opcode, client_id);
            send_nm_error(sock, ERR_INVALID_COMMAND, "Unknown command opcode.");
            break;
    }
}

// Main router for all opcodes from a registered SS.

void route_ss_request(uint32_t ss_id, int sock, MsgHeader* header, 
                      MsgPayload* payload, NameServerState* state){

    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    get_peer_info(sock, ip, sizeof(ip), &port);
    
    safe_printf("NM: REQ from SS %u [%s:%u] -> OpCode %u\n", ss_id, ip, port, header->opcode);

    switch(header->opcode) {
        case OP_SS_SYNC_FILE_INFO:
            handle_ss_sync_file(ss_id, header, &payload->ss_sync, state);
            break;

        case OP_SS_NM_UNDO_COMPLETE:
            handle_ss_undo_complete(ss_id, &payload->undo_complete, state);
            break;

        case OP_SS_NM_REDO_COMPLETE: // <-- ADD THIS BLOCK
            handle_ss_redo_complete(ss_id, &payload->redo_complete, state);
            break;
            
        case OP_SS_NM_REVERT_COMPLETE:
            handle_ss_revert_complete(ss_id, &payload->revert_complete, state);
            break;
            
        case OP_SS_NM_WRITE_COMPLETE:
            handle_ss_write_complete(ss_id, &payload->write_complete, state);
            break;

        case OP_HEARTBEAT_PONG:
            // TODO: handle_ss_pong(ss_id, state);
            break;

        default:
             safe_printf("NM: Unknown opcode %u from SS %u. Ignoring.\n", header->opcode, ss_id);
             break;
    }
}