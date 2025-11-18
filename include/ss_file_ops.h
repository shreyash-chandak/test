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
int copy_file(const char* src_path, const char* dst_path);

// --- P1 Functions ---
void handle_ss_read(StorageServerState* state, int client_sock, 
                    Payload_FileRequest* payload);

void handle_nm_ss_create(StorageServerState* state, int sock, Payload_FileRequest* payload);
void handle_nm_ss_delete(StorageServerState* state, int sock, Payload_FileRequest* payload);
void handle_ss_undo(StorageServerState* state, int client_sock, Payload_FileRequest* payload);
void handle_ss_redo(StorageServerState* state, int client_sock, Payload_FileRequest* payload);
void handle_ss_checkpoint(StorageServerState* state, int client_sock, Payload_CheckpointRequest* payload);
void handle_ss_revert(StorageServerState* state, int client_sock, Payload_CheckpointRequest* payload);
void handle_ss_viewcheckpoint(StorageServerState* state, int client_sock, Payload_CheckpointRequest* payload);
void handle_ss_listcheckpoints(StorageServerState* state, int client_sock, Payload_FileRequest* payload);
void handle_nm_ss_replicate(StorageServerState* state, int sock, Payload_ReplicateRequest* payload);
void handle_ss_replicate_read(StorageServerState* state, int sock, Payload_FileRequest* payload);
void handle_ss_stream(StorageServerState* state, int client_sock, Payload_FileRequest* payload);
void handle_nm_internal_read(StorageServerState* state, int sock, Payload_FileRequest* payload);

#endif // SS_FILE_OPS_H