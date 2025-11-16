#include "parse_command.h"
#include "utils.h"
#include "server_response.h"
#include "common.h"  
#include <ctype.h>

void print_help_menu(){
    safe_printf("── CLI Docs Help Menu ──\n");
    safe_printf("  view [-a] [-l]         : List files\n");
    safe_printf("  read <file>            : Read file content\n");
    safe_printf("  create <file>          : Create an empty file\n");
    safe_printf("  write <file> <sent_num>: Write to a file (interactive)\n");
    safe_printf("  undo <file>            : Revert last change to file\n");
    safe_printf("  redo <file>            : Re-apply last undone change\n");
    safe_printf("  info <file>            : Get file metadata\n");
    safe_printf("  delete <file>          : Delete a file\n");
    safe_printf("  stream <file>          : Stream file content\n");
    safe_printf("  list                   : List all users\n");
    safe_printf("  addaccess -R/-W <f> <u>: Grant access\n");
    safe_printf("  remaccess <file> <user>: Revoke access\n");
    safe_printf("  exec <file>            : Execute file as shell commands\n");
    safe_printf("\n  ── Access Requests ──\n");
    safe_printf("  reqaccess <file>       : Request access to a file\n");
    safe_printf("  listreqs <file>        : (Owner) List pending requests\n");
    safe_printf("  approve <f> <u> -R/-W  : (Owner) Approve a request\n");
    safe_printf("  deny <file> <user>     : (Owner) Deny a request\n");
    safe_printf("\n  ── General Commands ──\n");
    safe_printf("  help                   : Show this help menu\n");
    safe_printf("  clear                  : Clear the console\n");
    safe_printf("  exit                   : Quit the application\n");
    safe_printf("────────────────\n");
}

static void print_local_check(ParsedCommand* cmd) {
    safe_printf("────────LOCAL CHECK PASSED────────\n");
    
    switch(cmd->type) {
        case CMD_VIEW:
            safe_printf("  Command: VIEW\n");
            if (cmd->flag_a) safe_printf("  Flag: -a\n");
            if (cmd->flag_l) safe_printf("  Flag: -l\n");
            break;
        case CMD_READ:
            safe_printf("  Command: READ\n  File: %s\n", cmd->filename);
            break;
        case CMD_CREATE:
            safe_printf("  Command: CREATE\n  File: %s\n", cmd->filename);
            break;
        case CMD_WRITE:
            safe_printf("  Command: WRITE\n  File: %s\n  Sentence: %s\n", cmd->filename, cmd->sentence_num_str);
            break;
        case CMD_UNDO:
            safe_printf("  Command: UNDO\n  File: %s\n", cmd->filename);
            break;
        case CMD_REDO:
            safe_printf("  Command: REDO\n  File: %s\n", cmd->filename);
            break;
        case CMD_INFO:
            safe_printf("  Command: INFO\n  File: %s\n", cmd->filename);
            break;
        case CMD_DELETE:
            safe_printf("  Command: DELETE\n  File: %s\n", cmd->filename);
            break;
        case CMD_STREAM:
            safe_printf("  Command: STREAM\n  File: %s\n", cmd->filename);
            break;
        case CMD_LIST:
            safe_printf("  Command: LIST\n");
            break;
        case CMD_ADDACCESS:
            safe_printf("  Command: ADD ACCESS\n");
            if (cmd->flag_r) safe_printf("  Flag: -R\n");
            if (cmd->flag_w) safe_printf("  Flag: -W\n");
            safe_printf("  File: %s\n  User: %s\n", cmd->filename, cmd->username);
            break;
        case CMD_REMACCESS:
            safe_printf("  Command: REMOVE ACCESS\n  File: %s\n  User: %s\n", cmd->filename, cmd->username);
            break;
        case CMD_EXEC:
            safe_printf("  Command: EXECUTE\n  File: %s\n", cmd->filename);
            break;
        case CMD_REQACCESS:
            safe_printf("  Command: REQUEST ACCESS\n  File: %s\n", cmd->filename);
            break;
        case CMD_LISTREQS:
            safe_printf("  Command: LIST REQUESTS\n  File: %s\n", cmd->filename);
            break;
        case CMD_APPROVE:
            safe_printf("  Command: APPROVE REQUEST\n  File: %s\n  User: %s\n", cmd->filename, cmd->username);
            if (cmd->flag_r) safe_printf("  Flag: -R\n");
            if (cmd->flag_w) safe_printf("  Flag: -W\n");
            break;
    case CMD_DENY:
        safe_printf("  Command: DENY REQUEST\n  File: %s\n  User: %s\n", cmd->filename, cmd->username);
        break;
        // These are handled by the REPL, but we include them for completeness
        case CMD_HELP:
            safe_printf("  Command: HELP\n");
            break;
        case CMD_EXIT:
            safe_printf("  Command: EXIT\n");
            break;
        case CMD_EMPTY:
            safe_printf("  Command: EMPTY\n");
            break;
        case CMD_UNKNOWN:
        default:
             safe_printf("  Command: UNKNOWN\n");
             break;
    }
    safe_printf("───────────────────────────\n");
}

// ── Internal Function Prototypes ──
static const char* local_validate_command(ParsedCommand* cmd);
static void execute_command(ParsedCommand* cmd, int nm_socket);

ParsedCommand parse_command(const char* input){

    char input_copy[1024];
    strncpy(input_copy, input, 1023);
    input_copy[1023] = '\0';

    ParsedCommand cmd = {0};
    char* tokens[10];        // Max 10 tokens
    int token_count = 0;
    
    // Use strtok to split the input string by spaces
    char* token = strtok(input_copy, " ");
    while (token != NULL && token_count < 10) {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }

    if (token_count == 0) {
        cmd.type = CMD_EMPTY;
        return cmd;
    }

    // ── Command Identification (case-insensitive) ──
    for(char* p = tokens[0]; *p; ++p)
        *p = tolower(*p);

    if (strcmp(tokens[0], "view") == 0){
        cmd.type = CMD_VIEW;
        if (token_count > 1 && tokens[1][0] == '-') {
            if(strchr(tokens[1], 'a'))
                cmd.flag_a = true;
            if(strchr(tokens[1], 'l'))
                cmd.flag_l = true;
        }
    }

    else if (strcmp(tokens[0], "read") == 0){
        cmd.type = CMD_READ;
        if(token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }

    else if (strcmp(tokens[0], "create") == 0) {
        cmd.type = CMD_CREATE;
        if(token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "write") == 0){
        cmd.type = CMD_WRITE;
        if(token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if(token_count > 2)
            strncpy(cmd.sentence_num_str, tokens[2], 31);
    }
    else if (strcmp(tokens[0], "undo") == 0){
        cmd.type = CMD_UNDO;
        if (token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "redo") == 0){
        cmd.type = CMD_REDO;
        if (token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "info") == 0){
        cmd.type = CMD_INFO;
        if (token_count > 1) 
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "delete") == 0){
        cmd.type = CMD_DELETE;
        if (token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "stream") == 0){
        cmd.type = CMD_STREAM;
        if (token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "list") == 0){
        cmd.type = CMD_LIST;
    }
    else if (strcmp(tokens[0], "addaccess") == 0){
        cmd.type = CMD_ADDACCESS;
        if(token_count > 1){
            if(strcmp(tokens[1], "-R") == 0)
                cmd.flag_r = true;
            if(strcmp(tokens[1], "-W") == 0)
                cmd.flag_w = true;
        }
        if(token_count > 2)
            strncpy(cmd.filename, tokens[2], MAX_FILENAME_LEN - 1);
        if(token_count > 3)
            strncpy(cmd.username, tokens[3], MAX_USERNAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "remaccess") == 0){
        cmd.type = CMD_REMACCESS;
        if (token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if (token_count > 2)
            strncpy(cmd.username, tokens[2], MAX_USERNAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "reqaccess") == 0){
        cmd.type = CMD_REQACCESS;
        if(token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "listreqs") == 0){
        cmd.type = CMD_LISTREQS;
        if(token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "approve") == 0){
        cmd.type = CMD_APPROVE;
        if(token_count > 1) strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if(token_count > 2) strncpy(cmd.username, tokens[2], MAX_USERNAME_LEN - 1);
        if(token_count > 3) { // <filename> <user> <-R|-W>
            if(strcmp(tokens[3], "-R") == 0) cmd.flag_r = true;
            if(strcmp(tokens[3], "-W") == 0) cmd.flag_w = true;
        }
    }
    else if (strcmp(tokens[0], "deny") == 0){
        cmd.type = CMD_DENY;
        if(token_count > 1) strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if(token_count > 2) strncpy(cmd.username, tokens[2], MAX_USERNAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "exec") == 0){
        cmd.type = CMD_EXEC;
        if (token_count > 1)
            strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "help") == 0) {
        cmd.type = CMD_HELP;
    }
    else if (strcmp(tokens[0], "exit") == 0) {
        cmd.type = CMD_EXIT;
    }
    else if (strcmp(tokens[0], "clear") == 0) {
        cmd.type = CMD_CLEAR;
    }
    else{
        cmd.type = CMD_UNKNOWN;
    }

    return cmd;
}

//Validates and sends the command.

static const char* const ERR_MSG_FILENM = "Missing filename argument.";
static const char* const ERR_MSG_WRITE_ARGS = "WRITE requires a filename and a sentence number.";
static const char* const ERR_MSG_ACCESS_FLAG = "ADDACCESS requires '-R' (Read) or '-W' (Write) flag.";
static const char* const ERR_MSG_ACCESS_ARGS = "ADDACCESS/REMACCESS requires a filename and a username.";
static const char* const ERR_MSG_UNKNOWN = "Unknown command. Type 'help' for usage.";
static const char* const ERR_MSG_INVALID_SENTENCE_NUM = "WRITE sentence number must be a non-negative integer.";

static const char* local_validate_command(ParsedCommand* cmd) {
    
    switch (cmd->type) {
        // Commands that need NO args
        case CMD_LIST:
        case CMD_HELP:
        case CMD_EXIT:
        case CMD_EMPTY:
        case CMD_CLEAR:
            return NULL; // Success
        
        // Commands that need a filename

        case CMD_CREATE:
            if (strlen(cmd->filename) == 0) 
                return ERR_MSG_FILENM;
            // Check if the filename ends in .bak
            const char* ext = ".bak";
            size_t file_len = strlen(cmd->filename);
            size_t ext_len = strlen(ext);
            if (file_len > ext_len && strcmp(cmd->filename + file_len - ext_len, ext) == 0) {
                return "Invalid filename: Files cannot end in .bak as they are used for backups.";
            }
            return NULL;
        
        case CMD_READ:
        case CMD_UNDO:
        case CMD_REDO:
        case CMD_INFO:
        case CMD_DELETE:
        case CMD_STREAM:
        case CMD_EXEC:
            if (strlen(cmd->filename) == 0) 
                return ERR_MSG_FILENM;
            return NULL; // Success

        case CMD_VIEW:
            return NULL; // Success

        // Special case: WRITE
        case CMD_WRITE: {
            if (strlen(cmd->filename) == 0 || strlen(cmd->sentence_num_str) == 0) 
                return ERR_MSG_WRITE_ARGS;
            
            // Validate sentence number is a non-negative integer
            int sen_num = atoi(cmd->sentence_num_str);
            if (sen_num < 0) return ERR_MSG_INVALID_SENTENCE_NUM;

            // Check if the string contains only digits (slower, but safer validation)
            for (const char* p = cmd->sentence_num_str; *p; p++) {
                if (!isdigit(*p)) return ERR_MSG_INVALID_SENTENCE_NUM;
            }
            return NULL; // Success
        }

        // Special case: ADDACCESS
        case CMD_ADDACCESS:
            if (!cmd->flag_r && !cmd->flag_w) 
                return ERR_MSG_ACCESS_FLAG;
            // Fallthrough to check filename/username
        
        // Special case: REMACCESS
        case CMD_REMACCESS:
            if (strlen(cmd->filename) == 0 || strlen(cmd->username) == 0) 
                return ERR_MSG_ACCESS_ARGS;
            return NULL; // Success
        
        case CMD_REQACCESS:
        case CMD_LISTREQS: // We will make filename mandatory
            if (strlen(cmd->filename) == 0) return ERR_MSG_FILENM;
            return NULL;

        case CMD_APPROVE:
            if (!cmd->flag_r && !cmd->flag_w) return "APPROVE requires '-R' or '-W' flag.";
            // Fallthrough to check args
        case CMD_DENY:
            if (strlen(cmd->filename) == 0 || strlen(cmd->username) == 0)
                return "APPROVE/DENY requires a filename and a username.";
            return NULL;


        // Unknown
        case CMD_UNKNOWN:
        default:
            return ERR_MSG_UNKNOWN;
    }
}


void validate_and_send(ParsedCommand* cmd, int nm_socket) {
    const char* validation_error = local_validate_command(cmd);

    if (validation_error != NULL) {
        safe_printf("[Error] %s\n", validation_error);
        return;
    }
    
    // Validation passed, call the real network function
    execute_command(cmd, nm_socket);
}


static void execute_command(ParsedCommand* cmd, int nm_socket) {
    
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
            
            // --- NEW LOGIC: We are now in control of printing ---
            
            if (header.opcode == OP_NM_CLIENT_EXEC_OUTPUT) {
                // Just print the line, no headers/footers
                size_t data_len = header.length - sizeof(MsgHeader);
                payload.generic.buffer[data_len] = '\0';
                safe_printf("  %s\n", payload.generic.buffer); // <-- REMOVED PREFIX
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
            // --- END NEW LOGIC ---
        }
    }
}