#include "parse_command.h"
#include "utils.h"
#include "server_response.h"
#include "common.h"  
#include <ctype.h>
#define TO_COL_END  "\033[67G"

void print_help_menu(){
    safe_printf(FG_CYAN"┌─────────────────────────────────────────────────────────────────┐\n"COLOR_RESET);
    safe_printf(FG_CYAN"│                        Docs++ Help Menu                         │\n"COLOR_RESET);
    safe_printf(FG_CYAN"├─────────────────────────────────────────────────────────────────┤\n"COLOR_RESET);
    safe_printf(FG_CYAN"│"FG_GREEN"  view"FG_YELLOW" [-a] [-l]              "COLOR_RESET": List files"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  read"FG_YELLOW" <file>                 "COLOR_RESET": Read file content"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  create"FG_YELLOW" <file>               "COLOR_RESET": Create an empty file"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  write"FG_YELLOW" <file> <sent_num>     "COLOR_RESET": Write to a file (interactive)"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  undo"FG_YELLOW" <file>                 "COLOR_RESET": Revert last change to file"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  redo"FG_YELLOW" <file>                 "COLOR_RESET": Re-apply last undone change"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  info"FG_YELLOW" <file>                 "COLOR_RESET": Get file metadata"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  delete"FG_YELLOW" <file>               "COLOR_RESET": Delete a file"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  stream"FG_YELLOW" <file>               "COLOR_RESET": Stream file content"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  list                        "COLOR_RESET": List all users"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  addaccess"FG_YELLOW" -R/-W <f> <u>     "COLOR_RESET": Grant access"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  remaccess"FG_YELLOW" <file> <user>     "COLOR_RESET": Revoke access"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  exec"FG_YELLOW" <file>                 "COLOR_RESET": Execute file as shell commands"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│                                                                 │\n"COLOR_RESET);
    safe_printf(FG_CYAN"│"FG_MAGENTA"  [Access Requests]"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  reqaccess"FG_YELLOW" <file>            "COLOR_RESET": Request access to a file"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  listreqs"FG_YELLOW" <file>             "COLOR_RESET": (Owner) List pending requests"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  approve"FG_YELLOW" <f> <u> -R/-W       "COLOR_RESET": (Owner) Approve a request"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  deny"FG_YELLOW" <file> <user>          "COLOR_RESET": (Owner) Deny a request"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│                                                                 │\n"COLOR_RESET);
    safe_printf(FG_CYAN"│"FG_MAGENTA"  [Checkpoints]"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  checkpoint"FG_YELLOW" <file> <tag>     "COLOR_RESET": Create a checkpoint"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  revert"FG_YELLOW" <file> <tag>         "COLOR_RESET": Revert to a checkpoint"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  viewcheckpoint"FG_YELLOW" <file> <tag> "COLOR_RESET": View a checkpoint's content"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  listcheckpoints"FG_YELLOW" <file>      "COLOR_RESET": List all checkpoints for a file"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│                                                                 │\n"COLOR_RESET);
    safe_printf(FG_CYAN"│"FG_MAGENTA"  [General Commands]"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  help                        "COLOR_RESET": Show this help menu"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  clear                       "COLOR_RESET": Clear the console"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"│"FG_GREEN"  exit                        "COLOR_RESET": Quit the application"TO_COL_END FG_CYAN"│\n");
    safe_printf(FG_CYAN"└─────────────────────────────────────────────────────────────────┘\n"COLOR_RESET);
}

void print_local_check(ParsedCommand* cmd) {
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
        case CMD_CHECKPOINT:
            safe_printf("  Command: CHECKPOINT\n  File: %s\n  Tag: %s\n", cmd->filename, cmd->tag);
            break;
        case CMD_REVERT:
            safe_printf("  Command: REVERT\n  File: %s\n  Tag: %s\n", cmd->filename, cmd->tag);
            break;
        case CMD_VIEWCHECKPOINT:
            safe_printf("  Command: VIEWCHECKPOINT\n  File: %s\n  Tag: %s\n", cmd->filename, cmd->tag);
            break;
        case CMD_LISTCHECKPOINTS:
            safe_printf("  Command: LISTCHECKPOINTS\n  File: %s\n", cmd->filename);
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
    else if (strcmp(tokens[0], "checkpoint") == 0) {
        cmd.type = CMD_CHECKPOINT;
        if(token_count > 1) strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if(token_count > 2) strncpy(cmd.tag, tokens[2], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "revert") == 0) {
        cmd.type = CMD_REVERT;
        if(token_count > 1) strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if(token_count > 2) strncpy(cmd.tag, tokens[2], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "viewcheckpoint") == 0) {
        cmd.type = CMD_VIEWCHECKPOINT;
        if(token_count > 1) strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
        if(token_count > 2) strncpy(cmd.tag, tokens[2], MAX_FILENAME_LEN - 1);
    }
    else if (strcmp(tokens[0], "listcheckpoints") == 0) {
        cmd.type = CMD_LISTCHECKPOINTS;
        if(token_count > 1) strncpy(cmd.filename, tokens[1], MAX_FILENAME_LEN - 1);
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

        case CMD_LISTCHECKPOINTS:
            if (strlen(cmd->filename) == 0) return ERR_MSG_FILENM;
            return NULL; // Success
    
        case CMD_CHECKPOINT:
        case CMD_REVERT:
        case CMD_VIEWCHECKPOINT:
            if (strlen(cmd->filename) == 0) return ERR_MSG_FILENM;
            if (strlen(cmd->tag) == 0) return "Missing checkpoint tag argument.";
            // Prevent using .bak or other problematic tags
            if (strcmp(cmd->tag, "bak") == 0 || strchr(cmd->tag, '/') || strchr(cmd->tag, '\\')) {
                return "Invalid tag name. Cannot be 'bak' or contain slashes.";
            }
            return NULL; // Success
            
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
