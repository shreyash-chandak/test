#include "server_response.h"
#include "utils.h"
#include "common.h"
#include "protocol.h"
#include "parse_command.h"
#include "client_repl.h"

// ── Internal Function Prototypes ──
static void print_generic_response(MsgPayload* payload);
static void handle_ss_redirect(Payload_SSRedirect* redirect, ParsedCommand* original_cmd);
static void handle_ss_read_loop(int ss_socket);
static void handle_ss_write_loop(int ss_socket); 

/**
 * @brief Handles simple text-based replies from the NM (e.g., VIEW, LIST, INFO).
 * @param payload The payload containing the generic buffer.
 */
static void print_generic_response(MsgPayload* payload) {
    safe_printf("%s\n", payload->generic.buffer);
}

static void handle_ss_stream_loop(int ss_socket) {
    MsgHeader header;
    MsgPayload payload;

    safe_printf("  [Streaming file...]\n");

    while(1) {
        int status = recv_message(ss_socket, &header, &payload); 
        if (status <= 0) {
            safe_printf("\n[Error] Disconnected from SS during STREAM.\n");
            return;
        }

        // Check for the END packet first
        if (header.opcode == OP_SS_CLIENT_STREAM_END) { 
            safe_printf("\n  [Stream complete.]\n");
            return; // Done
        }

        // Check for an error
        if (header.opcode == OP_ERROR_RES || header.error != ERR_NONE) {
            safe_printf("\n[SS Error] %s\n", payload.error.message);
            return;
        }

        // Check for the DATA packet
        if (header.opcode == OP_SS_CLIENT_STREAM_DATA) { 
            // Print the word followed by a space
            printf("%s", payload.stream_data.word);
            fflush(stdout); // Force it to print *now*

            // ── Delay on the client, as per spec ──
            usleep(100000); // 100,000 microseconds = 0.1 seconds
        } else {
            safe_printf("\n[Error] Unexpected packet %u from SS.\n", header.opcode);
            return;
        }
    }
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

        // ── This is the actual data handling ──
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

/**
 * @brief Runs the interactive sub-REPL for a WRITE session.
 */
static void handle_ss_write_loop(int ss_socket) {
    char line[1024];
    MsgHeader header = {0};
    MsgPayload payload = {0};
    
    safe_printf("  [Sentence locked. You are now in WRITE mode.]\n");
    safe_printf("  Type '<word_index> <content>' to insert.\n");
    safe_printf("  Type 'ETIRW' to commit and exit.\n");

    while (1) {
        printf("  write> ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            safe_printf("\n[Error] Input error. Aborting WRITE session.\n");
            // We should just close the socket and let the SS timeout
            return;
        }

        line[strcspn(line, "\r\n")] = 0; // Chomp newline

        // ── Check for ETIRW ──
        if (strcmp(line, "ETIRW") == 0 || strcmp(line, "etirw") == 0) {
            safe_printf("  [Sending ETIRW...]\n");
            header.version = PROTOCOL_VERSION;
            header.opcode = OP_CLIENT_SS_ETIRW;
            header.length = sizeof(MsgHeader);
            
            if (send_message(ss_socket, &header, &payload) == -1) {
                safe_printf("[Error] Failed to send ETIRW. Disconnecting.\n");
                return;
            }
            
            // Wait for the final "OK"
            if (recv_message(ss_socket, &header, &payload) <= 0) {
                safe_printf("[Error] Disconnected waiting for ETIRW response.\n");
                return;
            }
            
            if (header.error != ERR_NONE) {
                safe_printf("[SS Error] Commit failed: %s\n", payload.error.message);
            } else {
                safe_printf("  [Write Successful. Commit complete.]\n");
            }
            return; // Exit loop
        }

        // ── Parse: <index> <content...> ──
        int word_index;
        char content[MAX_WRITE_CONTENT_LEN] = {0};
        
        // This format reads an int, skips whitespace, then reads
        // up to MAX_WRITE_CONTENT_LEN-1 characters of content.
        char format_string[64];
        snprintf(format_string, 64, "%%d %%%d[^\n]", MAX_WRITE_CONTENT_LEN - 1);

        int items = sscanf(line, format_string, &word_index, content);
        
        if (items != 2 || word_index < 0) {
            safe_printf("  [Invalid format. Use: <index> <content> or ETIRW]\n");
            continue;
        }

        // ── Send OP_CLIENT_SS_WRITE_DATA ──
        header.version = PROTOCOL_VERSION;
        header.opcode = OP_CLIENT_SS_WRITE_DATA;
        header.length = sizeof(MsgHeader) + sizeof(Payload_ClientSSWriteData);
        
        payload.write_data.word_index = (uint32_t)word_index;
        strncpy(payload.write_data.content, content, MAX_WRITE_CONTENT_LEN - 1);
        
        if (send_message(ss_socket, &header, &payload) == -1) {
            safe_printf("[Error] Failed to send WRITE_DATA. Disconnecting.\n");
            return;
        }
        
        safe_printf("  [Data sent.]\n");
    }
}

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
    // The SS needs our ID to manage locks properly
    ss_header.client_id = my_client_id;
    
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
        case CMD_REDO:
            ss_header.opcode = OP_CLIENT_SS_REDO_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(ss_payload.file_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        case CMD_CHECKPOINT:
            ss_header.opcode = OP_CLIENT_SS_CHECKPOINT_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_CheckpointRequest);
            strncpy(ss_payload.checkpoint_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(ss_payload.checkpoint_req.tag, original_cmd->tag, MAX_FILENAME_LEN - 1);
            break;
        case CMD_REVERT:
            ss_header.opcode = OP_CLIENT_SS_REVERT_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_CheckpointRequest);
            strncpy(ss_payload.checkpoint_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(ss_payload.checkpoint_req.tag, original_cmd->tag, MAX_FILENAME_LEN - 1);
            break;
        case CMD_VIEWCHECKPOINT:
            ss_header.opcode = OP_CLIENT_SS_VIEWCHECKPOINT_REQ;
            ss_header.length = sizeof(MsgHeader) + sizeof(Payload_CheckpointRequest);
            strncpy(ss_payload.checkpoint_req.filename, original_cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(ss_payload.checkpoint_req.tag, original_cmd->tag, MAX_FILENAME_LEN - 1);
            break;
        case CMD_LISTCHECKPOINTS:
            ss_header.opcode = OP_CLIENT_SS_LISTCHECKPOINTS_REQ;
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

    // ── 3. Handle the SS's response (THE NEW LOGIC) ──
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
                // We got the OK. Start the sub-REPL.
                handle_ss_write_loop(ss_socket);
            }
            break;
            
        case CMD_STREAM:
            handle_ss_stream_loop(ss_socket);
            break;
        case CMD_UNDO:
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                safe_printf("[Error] Disconnected from SS during UNDO.\n");
            } else if (ss_header.error != ERR_NONE) {
                safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                safe_printf("  [Undo Successful.]\n");
            }
            break; 
        case CMD_REDO: 
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                safe_printf("[Error] Disconnected from SS during REDO.\n");
            } else if (ss_header.error != ERR_NONE) {
                safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                safe_printf("  [Redo Successful.]\n");
            }
            break; // Done, close socket
        case CMD_CHECKPOINT:
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                safe_printf("[Error] Disconnected from SS during CHECKPOINT.\n");
            } else if (ss_header.error != ERR_NONE) {
                safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                safe_printf("  [Checkpoint Successful.]\n");
            }
            break; // Done

        case CMD_REVERT:
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                safe_printf("[Error] Disconnected from SS during REVERT.\n");
            } else if (ss_header.error != ERR_NONE) {
                safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                safe_printf("  [Revert Successful.]\n");
            }
            break; // Done

        case CMD_VIEWCHECKPOINT:
            // This re-uses the same logic as READ
            handle_ss_read_loop(ss_socket);
            break;

        case CMD_LISTCHECKPOINTS:
            // This receives a single generic buffer, just like VIEW from the NM
            if (recv_message(ss_socket, &ss_header, &ss_payload) <= 0) {
                safe_printf("[Error] Disconnected from SS during LISTCHECKPOINTS.\n");
            } else if (ss_header.error != ERR_NONE) {
                safe_printf("[SS Error] %s\n", ss_payload.error.message);
            } else {
                // Print the buffer from the SS
                print_generic_response(&ss_payload);
            }
            break;
        default:
            safe_printf("[Internal Error] Redirect for unknown command type.\n");
             break;
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

    // ── Process Successful Response ──
    safe_printf("── Server Response ──\n");
    switch(header->opcode) {
        // ── Generic "OK" from NM ──
        case OP_NM_CREATE_RES:
        case OP_NM_DELETE_RES:
        case OP_NM_ACCESS_RES:
            safe_printf("  Success.\n");
            break;
            
        // ── Data Replies from NM ──
        case OP_NM_VIEW_RES:
        case OP_NM_INFO_RES:
        case OP_NM_LIST_RES:
            print_generic_response(payload);
            break;
            
        // ── Redirects to SS ──
        case OP_NM_READ_RES:
        case OP_NM_WRITE_RES:
        case OP_NM_STREAM_RES:
        case OP_NM_UNDO_RES:
        case OP_NM_REDO_RES:
        case OP_NM_CHECKPOINT_RES:
        case OP_NM_REVERT_RES:
        case OP_NM_VIEWCHECKPOINT_RES:
        case OP_NM_LISTCHECKPOINTS_RES:
            handle_ss_redirect(&payload->redirect, original_cmd);
            break;
        
        // ── EXEC Replies from NM ──
        case OP_NM_CLIENT_EXEC_OUTPUT:
            size_t data_len = header->length - sizeof(MsgHeader);
            payload->generic.buffer[data_len] = '\0';
            // This opcode is sent multiple times
            safe_printf("  %s\n", payload->generic.buffer); // <-- REMOVED PREFIX
            fflush(stdout);
            break;

        case OP_NM_CLIENT_EXEC_END:
            safe_printf("  [Execution Finished]\n");
            break;
        
        case OP_NM_REQACCESS_RES:
            safe_printf("  [Access request sent successfully.]\n");
            break;
        case OP_NM_APPROVE_RES:
            safe_printf("  [Request processed successfully.]\n");
            break;
        case OP_NM_LISTREQS_RES:
            // This is a string response, same as VIEW
            print_generic_response(payload);
            break;
            
        default:
            safe_printf("  Received an unknown success response (OpCode: %u)\n", header->opcode);
            break;
    }
    if (header->opcode == OP_NM_CLIENT_EXEC_OUTPUT) return;
    safe_printf("────────────────\n");
}