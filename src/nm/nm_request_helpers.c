#include "nm_request_helpers.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"
#include "nm_persistence.h"
#include <time.h>

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
 
//Orchestrates with an SS to create the file.
void handle_create(uint32_t client_id, int sock, MsgHeader* header, 
                   Payload_FileRequest* payload, NameServerState* state) {

    pthread_mutex_lock(&state->create_file_mutex);

    // 1. Setup client response
    MsgHeader client_res_header = {0};
    client_res_header.version = PROTOCOL_VERSION;
    client_res_header.opcode = OP_NM_CREATE_RES; 
    client_res_header.client_id = client_id;
    client_res_header.length = sizeof(MsgHeader);
    client_res_header.error = ERR_NONE;

    // 2. Validate filename
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';
    if (strlen(payload->filename) == 0) {
        pthread_mutex_unlock(&state->create_file_mutex);
        send_nm_error_response(sock, client_id, header->opcode, ERR_INVALID_COMMAND, "Filename cannot be empty");
        return;
    }
    
    if (ts_hashmap_get(state->file_metadata_map, payload->filename)){
        pthread_mutex_unlock(&state->create_file_mutex);
        send_nm_error_response(sock, client_id, header->opcode, ERR_FILE_EXISTS, "File already exists");
        return;
    }

    // 3. --- REPLICATION: Pick TWO SSs ---
    uint32_t primary_id = 0, secondary_id = 0;
    StorageServerInfo* primary_ss = NULL;
    StorageServerInfo* secondary_ss = NULL;
    
    pick_replicas_for_create(state, &primary_ss, &primary_id, &secondary_ss, &secondary_id);
    
    if(primary_ss == NULL){
        pthread_mutex_unlock(&state->create_file_mutex);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "No Storage Servers available");
        return;
    }
    safe_printf("NM: CREATE '%s': Primary SS %u, Secondary SS %u\n", payload->filename, primary_id, secondary_id);

    // 4. --- Send CREATE to Primary SS ---
    MsgHeader ss_header = {0};
    MsgPayload ss_payload = {0}; // This is the REQUEST payload
    MsgPayload temp_res_payload = {0}; // A temporary buffer for the response
    
    ss_header.version = PROTOCOL_VERSION;
    ss_header.opcode = OP_NM_SS_CREATE_REQ;
    ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
    strncpy(ss_payload.file_req.filename, payload->filename, MAX_FILENAME_LEN - 1);
    
    if (send_onetime_ss_command(primary_ss, &ss_header, &ss_payload, &temp_res_payload) != ERR_NONE) {
        pthread_mutex_unlock(&state->create_file_mutex);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Primary Storage Server failed to create file");
        return;
    }

    // 5. --- Send CREATE to Secondary SS (if it exists) ---
    if (secondary_ss != NULL) {
        if (send_onetime_ss_command(secondary_ss, &ss_header, &ss_payload, &temp_res_payload) != ERR_NONE) {
            safe_printf("NM: Warning: Secondary SS %u failed to create file. Proceeding with one replica.\n", secondary_id);
            secondary_id = 0; // Mark as failed
        }
    }

    // 6. --- All SSs ACK'd. Update Metadata. ---
    safe_printf("NM: SSs ACK'd file creation. Updating metadata.\n");
    
    const char* creator_username = get_username_from_id(state, client_id);
    if (creator_username == NULL) creator_username = "unknown";
    
    FileMetadata* meta = malloc(sizeof(FileMetadata));
    pthread_mutex_init(&meta->meta_lock, NULL);
    pthread_mutex_lock(&meta->meta_lock);

    strncpy(meta->filename, payload->filename, MAX_FILENAME_LEN - 1);
    meta->ss_replicas[0] = primary_id;   
    meta->ss_replicas[1] = secondary_id; 
    strncpy(meta->owner_username, creator_username, MAX_USERNAME_LEN - 1);

    uint64_t now = (uint64_t)time(NULL);
    meta->file_size = 0;
    meta->created_at = now;
    meta->modified_at = now;
    meta->accessed_at = now;
    meta->access_list = ts_hashmap_create();
    char* owner_permission = strdup("RW");
    ts_hashmap_put(meta->access_list, strdup(creator_username), (void*)owner_permission);
    meta->pending_requests = ts_hashmap_create();
    
    pthread_mutex_unlock(&meta->meta_lock);
    
    // Add to main map and SS file lists
    ts_hashmap_put(state->file_metadata_map, meta->filename, meta);
    ts_hashmap_put(primary_ss->file_list, meta->filename, (void*)1); // (void*)1 is a placeholder
    if (secondary_ss) {
        ts_hashmap_put(secondary_ss->file_list, meta->filename, (void*)1);
    }

    // --- NEW LOG FORMAT ---
    persistence_log_op("META,CREATE,%s,%s,%u,%u,%llu",
                       meta->filename,
                       meta->owner_username,
                       meta->ss_replicas[0],
                       meta->ss_replicas[1],
                       (unsigned long long)meta->created_at);

    pthread_mutex_unlock(&state->create_file_mutex);
    send_message(sock, &client_res_header, NULL);
}

/**
 * @brief Handles P1 redirect commands (READ, WRITE, STREAM, UNDO).
 * Finds the correct SS and sends a redirect packet to the client.
 */
void handle_redirect(uint32_t client_id, int sock, MsgHeader* header, 
                     Payload_FileRequest* payload, NameServerState* state) {

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.client_id = client_id;
    
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';

    // 1. Find the file's metadata (from cache or main map)
    FileMetadata* meta = (FileMetadata*)lru_cache_get(state->file_cache, payload->filename);
    if (meta == NULL) {
        meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename);
        if (meta != NULL) {
            lru_cache_put(state->file_cache, payload->filename, meta);
        }
    }
    
    if (meta == NULL) {
        send_nm_error_response(sock, client_id, header->opcode, ERR_FILE_NOT_FOUND, "File not found");
        return;
    }

    // 2. Update access time
    pthread_mutex_lock(&meta->meta_lock);
    time_t now = time(NULL);
    persistence_log_op("META,SET_LAST_ACCESSED,%s,%ld\n", meta->filename, now);
    meta->accessed_at = now;
    pthread_mutex_unlock(&meta->meta_lock);

    // 3. Find the correct Storage Server
    StorageServerInfo* ss = NULL;
    bool is_write_op = false;
    
    switch(header->opcode) {
        // --- Write Operations (MUST use Primary) ---
        case OP_CLIENT_WRITE_REQ:
        case OP_CLIENT_UNDO_REQ:
        case OP_CLIENT_REDO_REQ:
        case OP_CLIENT_CHECKPOINT_REQ:
        case OP_CLIENT_REVERT_REQ:
            is_write_op = true;
            ss = get_primary_replica_ss(state, meta); // Gets SS for replicas[0]
            break;

        // --- Read Operations (Can use any Live Replica) ---
        case OP_CLIENT_READ_REQ:   
        case OP_CLIENT_STREAM_REQ:
        case OP_CLIENT_VIEWCHECKPOINT_REQ:
        case OP_CLIENT_LISTCHECKPOINTS_REQ:
            ss = get_live_replica_ss(state, meta); // Tries [0], then [1]
            break;

        default:
            send_nm_error_response(sock, client_id, header->opcode, ERR_UNKNOWN, "Invalid redirect operation");
            return;
    }

    // 4. Check if we found a valid, online SS
    if (ss == NULL) {
        if (is_write_op) {
            safe_printf("NM: File '%s' WRITE failed: Primary replica %u is offline.\n",
                payload->filename, meta->ss_replicas[0]);
            send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "File primary replica is offline for writing.");
        } else {
            safe_printf("NM: File '%s' READ failed: All replicas are offline.\n",
                payload->filename);
            send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "All replicas for this file are offline.");
        }
        return;
    }

    // 5. Build the redirect response opcode
    switch(header->opcode) {
        case OP_CLIENT_READ_REQ:   res_header.opcode = OP_NM_READ_RES; break;
        case OP_CLIENT_WRITE_REQ:  res_header.opcode = OP_NM_WRITE_RES; break;
        case OP_CLIENT_STREAM_REQ: res_header.opcode = OP_NM_STREAM_RES; break;
        case OP_CLIENT_UNDO_REQ:   res_header.opcode = OP_NM_UNDO_RES; break;
        case OP_CLIENT_REDO_REQ:   res_header.opcode = OP_NM_REDO_RES; break;
        case OP_CLIENT_CHECKPOINT_REQ: res_header.opcode = OP_NM_CHECKPOINT_RES; break;
        case OP_CLIENT_REVERT_REQ:     res_header.opcode = OP_NM_REVERT_RES; break;
        case OP_CLIENT_VIEWCHECKPOINT_REQ: res_header.opcode = OP_NM_VIEWCHECKPOINT_RES; break;
        case OP_CLIENT_LISTCHECKPOINTS_REQ: res_header.opcode = OP_NM_LISTCHECKPOINTS_RES; break;
    }

    res_header.length = sizeof(MsgHeader) + sizeof(Payload_SSRedirect);
    res_header.error = ERR_NONE;

    // 6. Populate the redirect payload with the live SS info
    strncpy(res_payload.redirect.ss_ip, ss->ip, MAX_IP_LEN - 1);
    res_payload.redirect.ss_port = ss->client_port;

    safe_printf("NM: Redirecting client %u for file '%s' to SS %u at %s:%u\n",
        client_id, payload->filename, ss->id, ss->ip, ss->client_port);

    // 7. Send the redirect packet
    if (send_message(sock, &res_header, &res_payload) == -1) {
        safe_printf("NM: Failed to send redirect to client %u\n", client_id);
    }
}

void handle_delete(uint32_t client_id, int sock, 
                          Payload_FileRequest* payload, NameServerState* state) {

    // 1. Get meta and user
    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename); 
    const char* username = get_username_from_id(state, client_id);

    // 2. Initial Checks
    if (meta == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_DELETE_REQ, ERR_FILE_NOT_FOUND, "File not found.");
        return;
    }
    if (username == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_DELETE_REQ, ERR_UNKNOWN, "Internal server error: Client session not found.");
        return;
    }
    if (strcmp(username, meta->owner_username) != 0) {
        send_nm_error_response(sock, client_id, OP_CLIENT_DELETE_REQ, ERR_ACCESS_DENIED, "Access denied: Only the file owner can delete this file.");
        return;
    }

    // 3. --- FORWARD TO SS REPLICAS ---
    bool primary_ok = false;
    
    // Build the delete packet
    MsgHeader ss_header = {0};
    ss_header.version = PROTOCOL_VERSION;
    ss_header.opcode = OP_NM_SS_DELETE_REQ;
    ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
    
    // This is the REQUEST payload
    MsgPayload ss_payload_req = {0}; 
    memcpy(&ss_payload_req.file_req, payload, sizeof(Payload_FileRequest));

    // This is a buffer to hold the RESPONSE (error) from the SS
    MsgPayload ss_payload_res = {0}; 

    // 4a. --- Send to Primary ---
    StorageServerInfo* primary_ss = get_primary_replica_ss(state, meta);
    if (primary_ss) {
        ErrorCode primary_err = send_onetime_ss_command(primary_ss, &ss_header, &ss_payload_req, &ss_payload_res);

        if (primary_err == ERR_NONE) {
            primary_ok = true;
        } else {
            // The Primary SS failed (e.g., ERR_FILE_LOCKED). Forward the error.
            safe_printf("NM: Failed to delete file on Primary SS %u. Error: %d\n", meta->ss_replicas[0], primary_err);
            send_nm_error_response(sock, client_id, OP_CLIENT_DELETE_REQ, 
                                   primary_err, // Forward the exact error code
                                   ss_payload_res.error.message[0] ? ss_payload_res.error.message : "Primary SS failed to delete.");
            return; // STOP
        }
    } else {
        safe_printf("NM: Primary SS %u not found. Assuming deleted.\n", meta->ss_replicas[0]);
        primary_ok = true; // Mark as "ok" since it's already gone
    }

    // 4b. --- Send to Secondary ---
    StorageServerInfo* secondary_ss = NULL;
    if (meta->ss_replicas[1] != 0) {
        char ss_key[16];
        snprintf(ss_key, 16, "%u", meta->ss_replicas[1]);
        secondary_ss = (StorageServerInfo*)ts_hashmap_get(state->ss_map, ss_key);
    }
    
    if (secondary_ss) {
        // Reset payload buffer for the next call
        memset(&ss_payload_res, 0, sizeof(MsgPayload));
        if (send_onetime_ss_command(secondary_ss, &ss_header, &ss_payload_req, &ss_payload_res) != ERR_NONE) {
            // Secondary failed, but primary succeeded. This is not a fatal error for the client.
            safe_printf("NM: Failed to delete file on Secondary SS %u.\n", meta->ss_replicas[1]);
        }
    } else {
        safe_printf("NM: Secondary SS %u not found. Assuming deleted.\n", meta->ss_replicas[1]);
    }

    // 5. --- CHECK RESULTS ---
    // The *Primary* must have succeeded. (This check is now handled in 4a)
    if (!primary_ok) {
        // This is a safeguard in case the primary_ss was NULL
        send_nm_error_response(sock, client_id, OP_CLIENT_DELETE_REQ, ERR_SS_DOWN, "Primary storage server could not be found.");
        return;
    }

    // 6. --- LOGGING (Write-Ahead) ---
    persistence_log_op("META,DELETE,%s\n", payload->filename);

    // 7. --- IN-MEMORY UPDATE ---
    void* old_meta = ts_hashmap_remove(state->file_metadata_map, payload->filename);
    lru_cache_remove(state->file_cache, payload->filename);
    
    // Remove from SS file lists
    if (primary_ss) ts_hashmap_remove(primary_ss->file_list, payload->filename);
    if (secondary_ss) ts_hashmap_remove(secondary_ss->file_list, payload->filename);
    
    if (old_meta) {
        free_file_metadata(old_meta);
    }

    // 8. --- Send Success to Client ---
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_DELETE_RES; 
    res_header.length = sizeof(MsgHeader);
    res_header.error = ERR_NONE;
    send_message(sock, &res_header, NULL);
}