#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include "ss_file_ops.h"
#include "ss_write_helpers.h"
#include "ss_handler.h"

// We need this helper struct for the thread
typedef struct {
    int socket_fd;
    StorageServerState* state;
} ThreadArgs;

/**
 * @brief Main router for requests from the NAME SERVER.
 * These are internal, administrative commands.
 */
void handle_nm_request(StorageServerState* state, int nm_sock, MsgHeader* header, MsgPayload* payload) {
    
    safe_printf("SS %u: Received command %u from NM\n", state->ss_id, header->opcode);

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
 * @brief The main thread routine for every new CLIENT connection.
 * MOVED FROM SS_MAIN.C
 */
void* handle_client_connection(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    int sock = args->socket_fd;
    StorageServerState* state = args->state;
    free(arg);

    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    get_peer_info(sock, ip, sizeof(ip), &port);

    safe_printf("SS: New connection from [%s:%u] on socket %d\n", ip, port, sock);

    MsgHeader header;
    MsgPayload payload;
    WriteSession* write_session = NULL; 

    if (recv_message(sock, &header, &payload) <= 0) {
        safe_printf("SS: [%s:%u] disconnected before first command.\n", ip, port);
        close(sock);
        return NULL;
    }

    safe_printf("SS %u: Command %u from Client ID %u [%s:%u]\n", 
        state->ss_id, header.opcode, header.client_id, ip, port);

    // 2. Route the *first* command
    switch (header.opcode) {
        
        case OP_NM_SS_CREATE_REQ:
            handle_nm_ss_create(state, sock, &payload.file_req);
            return NULL; // Handler closes socket
        
        case OP_NM_SS_DELETE_REQ:        
            handle_nm_ss_delete(state, sock, &payload.file_req);
            return NULL;

        case OP_CLIENT_SS_UNDO_REQ:
            handle_ss_undo(state, sock, &payload.file_req);
            return NULL; // Handler closes socket

        case OP_CLIENT_SS_REDO_REQ:
            handle_ss_redo(state, sock, &payload.file_req);
            return NULL; // Handler closes socket
        
        case OP_CLIENT_SS_CHECKPOINT_REQ:
            handle_ss_checkpoint(state, sock, &payload.checkpoint_req);
            return NULL; // Handler closes socket

        case OP_CLIENT_SS_REVERT_REQ:
            handle_ss_revert(state, sock, &payload.checkpoint_req);
            return NULL; // Handler closes socket

        case OP_CLIENT_SS_VIEWCHECKPOINT_REQ:
            handle_ss_viewcheckpoint(state, sock, &payload.checkpoint_req);
            return NULL; // Handler closes socket

        case OP_CLIENT_SS_LISTCHECKPOINTS_REQ:
            handle_ss_listcheckpoints(state, sock, &payload.file_req);
            return NULL; // Handler closes socket    

        case OP_NM_SS_REPLICATE_REQ:
            handle_nm_ss_replicate(state, sock, &payload.replicate_req);
            return NULL; // Handler closes socket

        case OP_SS_SS_REPLICATE_READ_REQ:
            handle_ss_replicate_read(state, sock, &payload.file_req);
            return NULL; // Handler closes socket
            
        case OP_CLIENT_SS_READ_REQ:
            handle_ss_read(state, sock, &payload.file_req);
            return NULL; // Handler closes socket
        
        case OP_CLIENT_SS_WRITE_START:
            handle_ss_write_start(state, sock, header.client_id, 
                                  &payload.write_start, &write_session);
            
            if (write_session == NULL) {
                safe_printf("SS: WRITE_START failed. Closing connection.\n");
                return NULL; // Handler already closed socket
            }
            safe_printf("SS: WRITE_START OK. Entering session loop for socket %d\n", sock);
            break;
            
        case OP_CLIENT_SS_STREAM_REQ: 
            handle_ss_stream(state, sock, &payload.file_req);
            return NULL;

        case OP_NM_SS_INTERNAL_READ_REQ:
        //safe_printf("DEBUG (SS): Received OP_NM_SS_INTERNAL_READ_REQ for %s\n",  payload.file_req.filename);
            handle_nm_internal_read(state, sock, &payload.file_req);
            return NULL; // Handler closes socket

        default:
            safe_printf("SS %u: Received unknown first opcode %u. Closing.\n",
                state->ss_id, header.opcode);
            send_ss_error(sock, ERR_INVALID_COMMAND, "Unknown or invalid initial command.");
            close(sock);
            return NULL;
    }

    // 3. --- If we are here, we are in a WRITE session ---
    while (recv_message(sock, &header, &payload) > 0) {
        
        switch(header.opcode) {
            
            case OP_CLIENT_SS_WRITE_DATA:
                handle_ss_write_data(write_session, &payload.write_data);
                break;
                
            case OP_CLIENT_SS_ETIRW:
                if (handle_ss_etirw(state, write_session) == 0) {
                    // Success!
                    MsgHeader res_header = {0};
                    res_header.version = PROTOCOL_VERSION;
                    res_header.opcode = OP_SS_CLIENT_ETIRW_RES;
                    res_header.error = ERR_NONE;
                    res_header.length = sizeof(MsgHeader);
                    send_message(sock, &res_header, NULL);
                } else {
                    // Failure
                    send_ss_error(sock, ERR_WRITE_FAILED, "Failed to commit changes to file.");
                }
                
                safe_printf("SS: ETIRW complete for [%s:%u].\n", ip, port);
                close(sock);
                return NULL;
                
            default:
                safe_printf("SS: Received invalid opcode %u during WRITE session.\n", header.opcode);
                send_ss_error(sock, ERR_INVALID_COMMAND, "Invalid command during write session.");
                break;
        }
    }

    // 4. --- Client disconnected mid-session ---
    safe_printf("SS: Client on socket %d disconnected mid-session.\n", sock);
    if (write_session) {
        // Call our new cleanup function to find and release the lock
        handle_ss_write_cleanup(state, write_session);
        // Now, free the session struct itself
        free_write_session(write_session);
    }
    close(sock);
    return NULL;
}