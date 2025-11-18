#include "nm_request_helpers.h"
#include "nm_request_helpers2.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"
#include "nm_persistence.h"
#include <time.h>
#include "nm_handler.h"
#include "protocol.h"
#include "nm_state.h"
#include "nm_access.h"
#include "lru_cache.h"

// --- Helpers for SS Selection ---

// Iterator callback to find two SSs
typedef struct {
    StorageServerInfo* ss[2];
    uint32_t ss_id[2];
    int count;
} FindTwoSSArgs;

typedef struct {
    StorageServerInfo** found_ss;
    uint32_t* ss_id;
} FindSSArgs;


StorageServerInfo* get_live_replica_ss(NameServerState* state, FileMetadata* meta) {
    char ss_key[16];
    
    // 1. Try Primary Replica (replicas[0])
    if (meta->ss_replicas[0] != 0) {
        snprintf(ss_key, 16, "%u", meta->ss_replicas[0]);
        StorageServerInfo* ss_info = (StorageServerInfo*)ts_hashmap_get(state->ss_map, ss_key);
        if (ss_info) {
            return ss_info; // Found primary, it's online.
        }
    }
    
    // 2. Try Secondary Replica (replicas[1])
    if (meta->ss_replicas[1] != 0) {
        snprintf(ss_key, 16, "%u", meta->ss_replicas[1]);
        StorageServerInfo* ss_info = (StorageServerInfo*)ts_hashmap_get(state->ss_map, ss_key);
        if (ss_info) {
            return ss_info; // Found secondary, it's online.
        }
    }
    
    // 3. Both are 0 or both are offline
    return NULL;
}

// Helper to find the primary SS for writes
StorageServerInfo* get_primary_replica_ss(NameServerState* state, FileMetadata* meta) {
    char ss_key[16];
    if (meta->ss_replicas[0] != 0) {
        snprintf(ss_key, 16, "%u", meta->ss_replicas[0]);
        return (StorageServerInfo*)ts_hashmap_get(state->ss_map, ss_key);
    }
    return NULL;
}


/**
 * @brief Asynchronously tells a secondary SS to replicate a file from a primary.
 * Fires the command and does not wait for a response.
 */
void trigger_async_replication(NameServerState* state, FileMetadata* meta) {

    // 1. Check if we have two valid, different replicas
    if (meta->ss_replicas[0] == 0 || meta->ss_replicas[1] == 0 || 
        meta->ss_replicas[0] == meta->ss_replicas[1]) {
        return; // No secondary to replicate to
    }

    // 2. Get info for both SSs
    StorageServerInfo* primary_ss = get_primary_replica_ss(state, meta);

    char secondary_key[16];
    snprintf(secondary_key, 16, "%u", meta->ss_replicas[1]);
    StorageServerInfo* secondary_ss = (StorageServerInfo*)ts_hashmap_get(state->ss_map, secondary_key);

    if (primary_ss == NULL || secondary_ss == NULL) {
        safe_printf("NM: AsyncReplication failed for '%s': Primary or Secondary SS is offline.\n", meta->filename);
        return;
    }

    // 3. Build the replication packet
    MsgHeader header = {0};
    MsgPayload payload = {0};

    header.version = PROTOCOL_VERSION;
    header.opcode = OP_NM_SS_REPLICATE_REQ;
    header.length = sizeof(MsgHeader) + sizeof(Payload_ReplicateRequest);

    strncpy(payload.replicate_req.filename, meta->filename, MAX_FILENAME_LEN - 1);
    strncpy(payload.replicate_req.primary_ss_ip, primary_ss->ip, MAX_IP_LEN - 1);
    payload.replicate_req.primary_ss_port = primary_ss->client_port;

    // 4. Send the command to the *Secondary* SS asynchronously
    // We use a new, one-time socket and do not wait for a reply.
    int ss_sock;
    struct sockaddr_in ss_addr;

    if ((ss_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { return; }
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(secondary_ss->client_port);
    inet_pton(AF_INET, secondary_ss->ip, &ss_addr.sin_addr);

    // This is non-blocking, but a full connect/send/close is fast
    if (connect(ss_sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) == 0) {
        safe_printf("NM: Sending REPLICATE command to Secondary SS %u for file '%s'.\n",
            secondary_ss->id, meta->filename);
        send_message(ss_sock, &header, &payload);
    }
    close(ss_sock); // Close immediately - "fire and forget"
}

// Send a command to a single SS and wait for its ACK
/**
 * @brief Sends a command to a single SS and waits for its ACK.
 * This is a blocking, synchronous operation.
 *
 * @param ss The StorageServerInfo to contact.
 * @param req_header The header for the REQUEST packet.
 * @param req_payload The payload for the REQUEST packet.
 * @param res_payload_out A pointer to a MsgPayload struct to be filled
 * with the SS's response (especially on error).
 * @return ErrorCode (ERR_NONE on success, or an error code on failure)
 */
 ErrorCode send_onetime_ss_command(StorageServerInfo* ss, MsgHeader* req_header, MsgPayload* req_payload, 
                                         MsgPayload* res_payload_out) {
    int ss_sock;
    struct sockaddr_in ss_addr;
    MsgHeader res_header; // Local header for the response

    // Clear the response payload buffer
    if (res_payload_out) {
        memset(res_payload_out, 0, sizeof(MsgPayload));
    }

    if ((ss_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("NM: socket (onetime)"); return ERR_SS_DOWN;
    }

    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss->client_port);
    if(inet_pton(AF_INET, ss->ip, &ss_addr.sin_addr) <= 0) {
        perror("NM: inet_pton (onetime)"); close(ss_sock); return ERR_SS_DOWN;
    }
    
    if (connect(ss_sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        perror("NM: connect (onetime)"); close(ss_sock); return ERR_SS_DOWN;
    }

    // Send the command
    if (send_message(ss_sock, req_header, req_payload) == -1) {
        safe_printf("NM: Failed to send onetime command to SS %u\n", ss->id);
        close(ss_sock); return ERR_SS_DOWN;
    }

    // Wait for the ACK
    if (recv_message(ss_sock, &res_header, res_payload_out) <= 0) { 
        safe_printf("NM: Did not receive ACK from SS %u\n", ss->id);
        close(ss_sock); return ERR_SS_DOWN;
    }
    
    close(ss_sock);
    
    if (res_header.error != ERR_NONE) {
        safe_printf("NM: SS %u returned error %d for onetime command\n", ss->id, res_header.error);
        return res_header.error; // Return the specific error
    }
    
    return ERR_NONE; // Success
}


void find_two_ss_callback(const char* key, void* value, void* arg) {
    FindTwoSSArgs* args = (FindTwoSSArgs*)arg;
    if (args->count < 2) {
        args->ss[args->count] = (StorageServerInfo*)value;
        args->ss_id[args->count] = (uint32_t)atoi(key);
        args->count++;
    }
}

// Pick two SSs for replication
void pick_replicas_for_create(NameServerState* state, StorageServerInfo** primary, uint32_t* primary_id, StorageServerInfo** secondary, uint32_t* secondary_id) {
    FindTwoSSArgs args = { {NULL, NULL}, {0, 0}, 0 };
    ts_hashmap_iterate(state->ss_map, find_two_ss_callback, &args);

    *primary = args.ss[0];
    *primary_id = args.ss_id[0];
    
    if (args.count > 1) {
        *secondary = args.ss[1];
        *secondary_id = args.ss_id[1];
    } else {
        *secondary = NULL; // No secondary available
        *secondary_id = 0;
    }
}

/**
 * @brief Handles an SS telling us it has a file.
 * This populates the NM's file_metadata_map on SS startup.
 */
void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_SSSyncFile* payload, NameServerState* state) {
    
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';
    if(strlen(payload->filename) == 0) return;

    // 1. Find the SS's info struct
    char ss_key[16];
    snprintf(ss_key, 16, "%u", ss_id);
    StorageServerInfo* ss_info = ts_hashmap_get(state->ss_map, ss_key);
    if (ss_info == NULL) {
        safe_printf("NM: CRITICAL: Could not find SS %u in ss_map during sync.\n", ss_id);
        return;
    }
    // Add to the SS's local file list
    ts_hashmap_put(ss_info->file_list, payload->filename, (void*)1);

    // 2. Check if we *already* know about this file
    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, payload->filename);
    
    if (meta) {
        pthread_mutex_lock(&meta->meta_lock);
        // Check if this SS is already a known replica
        if (meta->ss_replicas[0] == ss_id || meta->ss_replicas[1] == ss_id) {
            safe_printf("NM: SS %u re-sync'd file '%s'. (OK)\n", ss_id, payload->filename);
            meta->file_size = payload->file_size; // Update size
        } 
        // Check if the primary slot is orphaned
        else if (meta->ss_replicas[0] == 0) {
            safe_printf("NM: SS %u claiming orphaned file '%s' as Primary.\n", 
                ss_id, payload->filename);
            meta->ss_replicas[0] = ss_id;
            meta->file_size = payload->file_size;
        }
        // Check if the secondary slot is orphaned
        else if (meta->ss_replicas[1] == 0) {
             safe_printf("NM: SS %u claiming orphaned file '%s' as Secondary.\n", 
                ss_id, payload->filename);
            meta->ss_replicas[1] = ss_id;
            // We trust the primary's file size, so we don't update it here.
        }
        else {
            safe_printf("NM: SS %u sync'd file '%s', but replicas are full. (Conflict)\n",
                ss_id, payload->filename);
        }
        pthread_mutex_unlock(&meta->meta_lock);
    }
    
    else {
        // New file we've never seen. Add it.
        safe_printf("NM: SS %u sync'd new file '%s'. Adding as Primary.\n",
            ss_id, payload->filename);
        
        FileMetadata* new_meta = malloc(sizeof(FileMetadata));
        
        pthread_mutex_init(&new_meta->meta_lock, NULL);
        pthread_mutex_lock(&new_meta->meta_lock);

        strncpy(new_meta->filename, payload->filename, MAX_FILENAME_LEN - 1);
        new_meta->ss_replicas[0] = ss_id; // Set as primary
        new_meta->ss_replicas[1] = 0;   // No secondary yet
        strncpy(new_meta->owner_username, "unregistered", MAX_USERNAME_LEN - 1);
        
        new_meta->file_size = payload->file_size; 
        new_meta->created_at = 0; 
        new_meta->modified_at = 0; 
        new_meta->accessed_at = 0; 
        new_meta->access_list = ts_hashmap_create();
        char* owner_permission = strdup("R");
        ts_hashmap_put(new_meta->access_list, "everyone" , (void*)owner_permission);
        owner_permission = strdup("RW");
        ts_hashmap_put(new_meta->access_list, "unregistered" , (void*)owner_permission);
        
        new_meta->pending_requests = ts_hashmap_create();
        
        pthread_mutex_unlock(&new_meta->meta_lock);
        
        ts_hashmap_put(state->file_metadata_map, new_meta->filename, new_meta);
    }
}


void handle_ss_write_complete(uint32_t ss_id, Payload_SSNMWriteComplete* payload, NameServerState* state) {

    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename);

    if (meta == NULL) {
        safe_printf("NM: Received WRITE_COMPLETE for unknown file '%s' from SS %u. Updated Metadata.\n", payload->filename, ss_id);
        return;
    }
    
    safe_printf("NM: Received WRITE_COMPLETE for file '%s' from SS %u. Updated Metadata.\n", payload->filename, ss_id);
        
    pthread_mutex_lock(&meta->meta_lock);

    time_t now = time(NULL);

    // Log all changes
    persistence_log_op("META,WRITE,%s,%ld,%llu\n",
                           meta->filename,
                           (long)now,
                           (unsigned long long)payload->new_file_size);
    // Update in-memory struct
    meta->modified_at = (uint64_t)now;
    meta->accessed_at = (uint64_t)now;
    meta->file_size = payload->new_file_size;

    pthread_mutex_unlock(&meta->meta_lock);
    trigger_async_replication(state, meta);
}


void handle_ss_undo_complete(uint32_t ss_id, Payload_SSNMUndoComplete* payload, NameServerState* state) {

    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename); 

    if (meta == NULL) {
        safe_printf("NM: Received UNDO_COMPLETE for unknown file '%s' from SS %u\n", payload->filename, ss_id);
        return;
    }
    safe_printf("NM: Received UNDO_COMPLETE for file '%s' from SS %u\n", payload->filename, ss_id);
    pthread_mutex_lock(&meta->meta_lock);

    time_t now = time(NULL);

    // --- Log the UNDO operation ---
    persistence_log_op("META,UNDO,%s,%ld,%llu\n",
                       meta->filename,
                       (long)now,
                       (unsigned long long)payload->new_file_size); 

    // An UNDO is a write operation, so update all metadata
    meta->modified_at = (uint64_t)now;
    meta->accessed_at = (uint64_t)now;
    meta->file_size = payload->new_file_size;

    pthread_mutex_unlock(&meta->meta_lock);
    trigger_async_replication(state, meta);
}

void handle_ss_redo_complete(uint32_t ss_id, Payload_SSNMRedoComplete* payload, NameServerState* state) {

    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename); 

    if (meta == NULL) {
        safe_printf("NM: Received REDO_COMPLETE for unknown file '%s' from SS %u\n", payload->filename, ss_id);
        return;
    }
    safe_printf("NM: Received REDO_COMPLETE for file '%s' from SS %u\n", payload->filename, ss_id);
    pthread_mutex_lock(&meta->meta_lock);

    time_t now = time(NULL);

    // --- Log the REDO operation ---
    persistence_log_op("META,REDO,%s,%ld,%llu", // <-- Note the new log type
                       meta->filename,
                       (long)now,
                       (unsigned long long)payload->new_file_size); 

    // A REDO is a write operation, so update all metadata
    meta->modified_at = (uint64_t)now;
    meta->accessed_at = (uint64_t)now;
    meta->file_size = payload->new_file_size;

    pthread_mutex_unlock(&meta->meta_lock);
    trigger_async_replication(state, meta);
}

void handle_ss_revert_complete(uint32_t ss_id, Payload_SSNMRevertComplete* payload, NameServerState* state) {

    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename); 

    if (meta == NULL) {
        safe_printf("NM: Received REVERT_COMPLETE for unknown file '%s' from SS %u\n", payload->filename, ss_id);
        return;
    }
    safe_printf("NM: Received REVERT_COMPLETE for file '%s' from SS %u\n", payload->filename, ss_id);
    pthread_mutex_lock(&meta->meta_lock);

    time_t now = time(NULL);

    // Log the REVERT operation
    persistence_log_op("META,REVERT,%s,%ld,%llu",
                       meta->filename,
                       (long)now,
                       (unsigned long long)payload->new_file_size); 

    // A REVERT is a write operation, so update all metadata
    meta->modified_at = (uint64_t)now;
    meta->accessed_at = (uint64_t)now;
    meta->file_size = payload->new_file_size;

    pthread_mutex_unlock(&meta->meta_lock);
    trigger_async_replication(state, meta);
}