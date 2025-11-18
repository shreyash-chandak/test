#ifndef PARSE_COMMAND_H
#define PARSE_COMMAND_H

#include <stdint.h>
#include <stdbool.h>
#include "protocol.h" 
// For MAX_FILENAME_LEN etc

typedef enum {
    CMD_UNKNOWN,
    CMD_VIEW, 
    CMD_READ,  
    CMD_CREATE,  
    CMD_WRITE,  
    CMD_UNDO, 
    CMD_REDO,
    CMD_INFO, 
    CMD_DELETE, 
    CMD_STREAM,
    CMD_LIST,
    CMD_ADDACCESS, 
    CMD_REMACCESS,  
    CMD_EXEC, 
    CMD_HELP,
    CMD_EXIT,
    CMD_EMPTY,
    CMD_CLEAR,
    CMD_REQACCESS,  
    CMD_LISTREQS,   
    CMD_APPROVE,    
    CMD_DENY,
    // --- CHECKPOINTS ---
    CMD_CHECKPOINT,
    CMD_VIEWCHECKPOINT,
    CMD_REVERT,
    CMD_LISTCHECKPOINTS
} CommandType;

// Holds the structured data from a parsed user command.

typedef struct {
    CommandType type;
    
    // Flags (primarily for VIEW)
    bool flag_a; 
    bool flag_l; 
    
    // Specific flags for ADDACCESS
    bool flag_r;
    bool flag_w;

    // Arguments
    char filename[MAX_FILENAME_LEN];
    char username[MAX_USERNAME_LEN];
    char tag[MAX_FILENAME_LEN];
    char sentence_num_str[32]; 
    // Store as string for validation

} ParsedCommand;

// Parses the raw user input string into a ParsedCommand struct.
ParsedCommand parse_command(const char* input);

//Validates the command and (if valid) sends it to the server.
void validate_and_send(ParsedCommand* cmd, int nm_socket);

void print_help_menu();

void print_local_check(ParsedCommand* cmd);
void execute_command(ParsedCommand* cmd, int nm_socket);

#endif