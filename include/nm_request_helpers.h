#ifndef NM_REQUEST_HELPERS_H
#define NM_REQUEST_HELPERS_H

#include "protocol.h"
#include "nm_structs.h"

// --- HELPER PROTOTYPES ---

/**
 * @brief Finds a live, online SS for READ-ONLY operations.
 * Tries Primary (replicas[0]), then Secondary (replicas[1]).
 * @return A valid StorageServerInfo* if a live replica is found, else NULL.
 */
StorageServerInfo* get_live_replica_ss(NameServerState* state, FileMetadata* meta);

/**
 * @brief Finds the primary SS for WRITE operations.
 * ONLY checks Primary (replicas[0]).
 * @return A valid StorageServerInfo* if the primary is online, else NULL.
 */
StorageServerInfo* get_primary_replica_ss(NameServerState* state, FileMetadata* meta);

/**
 * @brief Asynchronously tells a secondary SS to replicate a file from a primary.
 */
void trigger_async_replication(NameServerState* state, FileMetadata* meta);

// --- EXISTING PROTOTYPES ---

void handle_create(uint32_t client_id, int sock, MsgHeader* header, 
                   Payload_FileRequest* payload, NameServerState* state);

void handle_delete(uint32_t client_id, int sock, 
                          Payload_FileRequest* payload, NameServerState* state);

void handle_redirect(uint32_t client_id, int sock, MsgHeader* header, 
                     Payload_FileRequest* payload, NameServerState* state);

void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_SSSyncFile* payload, NameServerState* state);

void pick_replicas_for_create(NameServerState* state, StorageServerInfo** primary, 
                            uint32_t* primary_id, StorageServerInfo** secondary, 
                            uint32_t* secondary_id);

ErrorCode send_onetime_ss_command(StorageServerInfo* ss, MsgHeader* req_header, 
                                MsgPayload* req_payload, MsgPayload* res_payload_out);
                                
#endif // NM_REQUEST_HELPERS_H