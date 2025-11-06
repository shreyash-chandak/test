#include "server_response.h"
#include "utils.h"
#include "common.h"
#include "protocol.h"
#include "parse_command.h"

// --- Internal Function Prototypes ---

/**
 * @brief Handles simple text-based replies from the NM (e.g., VIEW, LIST, INFO).
 * @param payload The payload containing the generic buffer.
 */
static void print_generic_response(MsgPayload* payload) {
    safe_printf("%s\n", payload->generic.buffer);
}

/**
 * @brief Handles the full READ data loop with the SS.
 */
static void handle_ss_read_loop(int ss_socket) {
    MsgHeader header;
    MsgPayload payload;
    bool first_chunk = true;
    size_t total_bytes = 0;

    // We loop, receiving chunks until the SS hangs up
    // or we get a "last_chunk" packet.
    while (1) {
        int status = recv_message(ss_socket, &header, &payload);
        
        if (status <= 0) {
            safe_printf("[Error] Disconnected from SS during READ operation.\n");
            return;
        }

        // Check for an error packet *during* the read
        if (header.opcode == OP_ERROR_RES || header.error != ERR_NONE) {
            safe_printf("[SS Error] %s\n", payload.error.message);
            return;
        }

        if (header.opcode != OP_SS_CLIENT_READ_RES) {
            safe_printf("[Error] Received unexpected opcode %u from SS.\n", header.opcode);
            return;
        }

        // --- This is the actual data handling ---
        if (first_chunk) {
            safe_printf("  [File Size: %u bytes]\n", payload.file_chunk.file_size);
            first_chunk = false;
        }
        
        if (payload.file_chunk.data_len > 0) {
            // Print the chunk. We use fwrite because it's binary-safe
            // and won't stop on an embedded null char.
            fwrite(payload.file_chunk.data, 1, payload.file_chunk.data_len, stdout);
            total_bytes += payload.file_chunk.data_len;
        }

        if (payload.file_chunk.is_last_chunk) {
            // We're done.
            if (total_bytes == 0 && payload.file_chunk.file_size == 0) {
                safe_printf("  [File is empty]\n");
            } else {
                // Add a newline just in case the file didn't have one
                safe_printf("\n"); 
            }
            safe_printf("  [End of file. Total %zu bytes received.]\n", total_bytes);
            break; // Exit the loop
        }
    }
}


// 3 way handshake

static void handle_ss_redirect(Payload_SSRedirect* redirect, ParsedCommand* original_cmd) {
    safe_printf("  [Redirecting to Storage Server at %s:%u...]\n",
        redirect->ss_ip, redirect->ss_port);

    // 1. Establish the new, direct connection to the SS
    int ss_socket;
    struct sockaddr_in ss_addr;

    if ((ss_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        safe_printf("[Error] Could not create socket for SS connection.\n");
        return;
    }

    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(redirect->ss_port);
    if (inet_pton(AF_INET, redirect->ss_ip, &ss_addr.sin_addr) <= 0) {
        safe_printf("[Error] Invalid SS IP address provided by NM.\n");
        close(ss_socket);
        return;
    }

    if (connect(ss_socket, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        safe_printf("[Error] Could not connect to Storage Server at %s:%u.\n",
            redirect->ss_ip, redirect->ss_port);
        close(ss_socket);
        return;
    }

    safe_printf("  [Connected to SS. Sending operation...]\n");

    // 2. Build and send the *real* request packet to the SS
    MsgHeader ss_header = {0};
    MsgPayload ss_payload = {0};
    ss_header.version = PROTOCOL_VERSION;
    ss_header.error = ERR_NONE;
    
    // Use the original command to decide which SS opcode to send
    switch (original_cmd->type) {
        case CMD_READ:
            ss_header.opcode = OP_CLIENT_SS_READ_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(ss_payload.file_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        case CMD_WRITE:
            ss_header.opcode = OP_CLIENT_SS_WRITE_START;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_ClientSSWriteStart);
            strncpy(ss_payload.write_start.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            ss_payload.write_start.sentence_index = (uint32_t)atoi(original_cmd->sentence_num_str);
            break;
        case CMD_STREAM:
            ss_header.opcode = OP_CLIENT_SS_STREAM_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(ss_payload.file_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        case CMD_UNDO:
            ss_header.opcode = OP_CLIENT_SS_UNDO_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(ss_payload.file_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        default:
            safe_printf("[Internal Error] Redirect for unknown command type.\n");
            close(ss_socket);
            return;
    }
    
    if (send_message(ss_socket, &ss_header, &ss_payload) == -1) {
        safe_printf("[Error] Failed to send request to SS.\n");
        close(ss_socket);
        return;
    }

    // --- 3. Handle the SS's response (THE NEW LOGIC) ---
    // We've sent the request. Now we handle the response,
    // which might be a single packet (WRITE) or a loop (READ).
    
    switch (original_cmd->type) {
        
        case CMD_READ:
            // This function will now handle the entire multi-chunk loop
            handle_ss_read_loop(ss_socket);
            break;
            
        case CMD_WRITE:
            // This is a simple, single-packet response
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                safe_printf("[Error] Disconnected from SS during WRITE_START.\n");
            } else if (ss_header.error != ERR_NONE) {
                safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                safe_printf("  [SS Operation Successful. Entering WRITE mode...]\n");
                // TODO: Start the real interactive write REPL
            }
            break;
            
        case CMD_STREAM:
        case CMD_UNDO:
            // TODO: Implement these handlers
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                 safe_printf("[Error] Disconnected from SS during operation.\n");
            } else if (ss_header.error != ERR_NONE) {
                 safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                 safe_printf("  [SS Operation Successful]\n");
            }
            break;
        
        default:
             break; // Should be impossible
    }

    // 4. Close the temporary connection
    close(ss_socket);
    safe_printf("  [SS Connection Closed]\n");
}

/**
 * @brief Main router for handling all responses from the Name Server.
 */
void handle_server_response(MsgHeader* header, MsgPayload* payload, ParsedCommand* original_cmd) {
    
    // Check for a protocol-level error first
    if (header->error != ERR_NONE) {
        safe_printf("[Server Error] %s (Code: %d)\n", payload->error.message, header->error);
        return;
    }

    // --- Process Successful Response ---
    safe_printf("--- Server Response ---\n");
    switch(header->opcode) {
        // --- Generic "OK" from NM ---
        case OP_NM_CREATE_RES:
        case OP_NM_DELETE_RES:
        case OP_NM_ACCESS_RES:
            safe_printf("  Success.\n");
            break;
            
        // --- Data Replies from NM ---
        case OP_NM_VIEW_RES:
        case OP_NM_INFO_RES:
        case OP_NM_LIST_RES:
            print_generic_response(payload);
            break;
            
        // --- Redirects to SS ---
        case OP_NM_READ_RES:
        case OP_NM_WRITE_RES:
        case OP_NM_STREAM_RES:
        case OP_NM_UNDO_RES:
            handle_ss_redirect(&payload->redirect, original_cmd);
            break;
        
        // --- EXEC Replies from NM ---
        case OP_NM_CLIENT_EXEC_OUTPUT:
            // This opcode is sent multiple times
            safe_printf("  EXEC: %s\n", payload->generic.buffer);
            break;
        case OP_NM_CLIENT_EXEC_END:
            safe_printf("  [Execution Finished]\n");
            break;
            
        default:
            safe_printf("  Received an unknown success response (OpCode: %u)\n", header->opcode);
            break;
    }
    safe_printf("-----------------------\n");
}