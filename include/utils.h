#ifndef UTILS_H
#define UTILS_H

#include "protocol.h"
#include "nm_structs.h"
#include <pthread.h>

typedef enum {
    PERM_READ,
    PERM_WRITE
} PermissionLevel;


void init_printf_mutex();
void destroy_printf_mutex();
void safe_printf(const char* format, ...);

// --- Networking Functions ---

int send_message(int sock, MsgHeader* header, MsgPayload* payload);
int recv_message(int sock, MsgHeader* header, MsgPayload* payload);
uint32_t compute_checksum(const void* data, size_t length);
void send_nm_error_response(int sock, uint32_t client_id, OpCode original_opcode, 
                          ErrorCode error, const char* message);

void send_nm_error(int sock, ErrorCode error, const char* message);

bool check_access(FileMetadata* meta, const char* username, PermissionLevel required_level);

const char* get_username_from_id(NameServerState* state, uint32_t client_id);


// ANSI Color Codes (cause why not)
#define COLOR_RESET "\033[0m"
#define BRIGHTBLUE "\033[94m"
#define LIGHTRED "\033[91m"
#define YELLOW "\033[93m"

#endif
