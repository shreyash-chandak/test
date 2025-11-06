#ifndef SS_FILE_OPS_H
#define SS_FILE_OPS_H

#include "ss_structs.h"

// --- From ss_main.c ---
void init_ss_state(StorageServerState* state, const char* data_dir, 
                   const char* nm_ip, uint16_t nm_port, uint16_t client_port,
                   const char* public_ip);

// --- From ss_file_ops.c ---
int ss_create_file(StorageServerState* state, const char* filename);
void free_file_lock_info(void* val);

// --- NEW P1 FUNCTION ---
/**
 * @brief Handles a client's READ request.
 * Acquires a read lock, reads the file, and sends it
 * back to the client in chunks.
 */
void handle_ss_read(StorageServerState* state, int client_sock, 
                    Payload_FileRequest* payload);

#endif // SS_FILE_OPS_H