#include "parse_command.h"
#include "utils.h"
#include "server_response.h"
#include "common.h"  
#include <ctype.h>

void execute_command(ParsedCommand* cmd, int nm_socket) {
    
    print_local_check(cmd);
    
    MsgHeader header = {0};
    MsgPayload payload = {0};

    // ── 1. Set Universal Header Fields ──
    header.version = PROTOCOL_VERSION;
    header.client_id = 0;
    header.error = ERR_NONE;

    // ── 2. Build Packet Based on Command Type ──
    switch(cmd->type) {
        
        case CMD_VIEW:
            header.opcode = OP_CLIENT_VIEW_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_ClientViewReq);
            if (cmd->flag_a) payload.client_view_req.flags |= VIEW_FLAG_A;
            if (cmd->flag_l) payload.client_view_req.flags |= VIEW_FLAG_L;
            break;
            
        case CMD_READ:
            header.opcode = OP_CLIENT_READ_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_CREATE:
            header.opcode = OP_CLIENT_CREATE_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_WRITE:
            header.opcode = OP_CLIENT_WRITE_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_ClientWriteReq);
            strncpy(payload.write_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            payload.write_req.sentence_index = (uint32_t)atoi(cmd->sentence_num_str);
            break;

        case CMD_UNDO:
            header.opcode = OP_CLIENT_UNDO_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_REDO:
            header.opcode = OP_CLIENT_REDO_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_INFO:
            header.opcode = OP_CLIENT_INFO_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_DELETE:
            header.opcode = OP_CLIENT_DELETE_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_STREAM:
            header.opcode = OP_CLIENT_STREAM_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_LIST:
            header.opcode = OP_CLIENT_LIST_REQ;
            header.length = sizeof(MsgHeader); // No payload
            break;

        case CMD_ADDACCESS:
            header.opcode = OP_CLIENT_ACCESS_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_ClientAccessReq);
            strncpy(payload.access_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.access_req.username, cmd->username, MAX_USERNAME_LEN - 1);
            if (cmd->flag_r) payload.access_req.flags |= ACCESS_FLAG_READ_ADD;
            if (cmd->flag_w) payload.access_req.flags |= ACCESS_FLAG_WRITE_ADD;
            break;

        case CMD_REMACCESS:
            header.opcode = OP_CLIENT_ACCESS_REQ; // Same opcode as ADD
            header.length = sizeof(MsgHeader) + sizeof(Payload_ClientAccessReq);
            strncpy(payload.access_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.access_req.username, cmd->username, MAX_USERNAME_LEN - 1);
            payload.access_req.flags = ACCESS_FLAG_REMOVE;
            break;

        case CMD_EXEC:
            header.opcode = OP_CLIENT_EXEC_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;

        case CMD_REQACCESS:
            header.opcode = OP_CLIENT_REQACCESS_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        case CMD_LISTREQS:
            header.opcode = OP_CLIENT_LISTREQS_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        case CMD_APPROVE:
            header.opcode = OP_CLIENT_APPROVE_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_ClientAccessReq);
            strncpy(payload.access_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.access_req.username, cmd->username, MAX_USERNAME_LEN - 1);
            if (cmd->flag_r) payload.access_req.flags |= ACCESS_FLAG_READ_ADD;
            if (cmd->flag_w) payload.access_req.flags |= ACCESS_FLAG_WRITE_ADD;
            break;
        case CMD_DENY:
            header.opcode = OP_CLIENT_APPROVE_REQ; // Same opcode
            header.length = sizeof(MsgHeader) + sizeof(Payload_ClientAccessReq);
            strncpy(payload.access_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.access_req.username, cmd->username, MAX_USERNAME_LEN - 1);
            payload.access_req.flags = ACCESS_FLAG_REMOVE;
            break;
        case CMD_CHECKPOINT:
            header.opcode = OP_CLIENT_CHECKPOINT_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_CheckpointRequest);
            strncpy(payload.checkpoint_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.checkpoint_req.tag, cmd->tag, MAX_FILENAME_LEN - 1);
            break;
        case CMD_REVERT:
            header.opcode = OP_CLIENT_REVERT_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_CheckpointRequest);
            strncpy(payload.checkpoint_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.checkpoint_req.tag, cmd->tag, MAX_FILENAME_LEN - 1);
            break;
        case CMD_VIEWCHECKPOINT:
            header.opcode = OP_CLIENT_VIEWCHECKPOINT_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_CheckpointRequest);
            strncpy(payload.checkpoint_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            strncpy(payload.checkpoint_req.tag, cmd->tag, MAX_FILENAME_LEN - 1);
            break;
        case CMD_LISTCHECKPOINTS:
            header.opcode = OP_CLIENT_LISTCHECKPOINTS_REQ;
            header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
            strncpy(payload.file_req.filename, cmd->filename, MAX_FILENAME_LEN - 1);
            break;
        default:
            safe_printf("[Internal Error] execute_command called with unhandled command type.\n");
            return;
    }
    
    if (send_message(nm_socket, &header, &payload) == -1) {
        safe_printf("[Network Error] Failed to send command to Name Server.\n");
        return;
    }
    // Note: This is a *blocking* call.
    //safe_printf("DEBUG (Client): Sent request. Now waiting for first response from NM...\n");
    
    if (recv_message(nm_socket, &header, &payload) <= 0) {
        safe_printf("[Network Error] Disconnected from Name Server. Exiting.\n");
        close(nm_socket);
        exit(EXIT_FAILURE); // <── This is the new, fatal action
    }

    // ── 5. Process the server's reply ──
    handle_server_response(&header, &payload, cmd);
    

    // Special handling for EXEC, which sends multiple packets
    if (header.opcode == OP_NM_CLIENT_EXEC_OUTPUT) {
        
        // The first line was already printed by handle_server_response.
        // This loop will now print the rest of the output cleanly.
        
        while(1) {
            if (recv_message(nm_socket, &header, &payload) <= 0) {
                 safe_printf("[Network Error] Disconnected during EXEC output. Exiting.\n");
                 close(nm_socket);
                 exit(EXIT_FAILURE);
            }
            
            if (header.opcode == OP_NM_CLIENT_EXEC_OUTPUT) {
                // Just print the line, no headers/footers
                size_t data_len = header.length - sizeof(MsgHeader);
                payload.generic.buffer[data_len] = '\0';
                safe_printf("  %s\n", payload.generic.buffer);
                fflush(stdout);
            }
            else if (header.opcode == OP_NM_CLIENT_EXEC_END) {
                // This packet is normally handled by handle_server_response,
                // but we're in our own loop. Print the final message.
                safe_printf("  [Execution Finished]\n");
                safe_printf("────────────────\n"); // Manually print the *final* footer
                break; // Exit the loop
            } 
            else if (header.error != ERR_NONE) {
                // An error packet was received.
                safe_printf("[Server Error] %s (Code: %d)\n", payload.error.message, header.error);
                safe_printf("────────────────\n"); // Manually print the *final* footer
                break; // Exit the loop
            }
            else {
                safe_printf("[Internal Error] Unexpected packet %u during EXEC.\n", header.opcode);
                break;
            }
        }
    }
}