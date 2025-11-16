#include "nm_request_helpers.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"
#include "nm_persistence.h"
#include <time.h>

// --- Helpers for SS Selection (Unchanged) ---
typedef struct {
    StorageServerInfo** found_ss;
    uint32_t* ss_id;
} FindSSArgs;

static void find_first_ss_callback(const char* key, void* value, void* arg) {
    FindSSArgs* args = (FindSSArgs*)arg;
    if (*(args->found_ss) == NULL) {
        *(args->found_ss) = (StorageServerInfo*)value;
        *(args->ss_id) = (uint32_t)atoi(key);
    }
}

static StorageServerInfo* pick_ss_for_create(NameServerState* state, uint32_t* selected_ss_id){
    StorageServerInfo* ss = NULL;
    FindSSArgs args;
    args.found_ss = &ss;
    args.ss_id = selected_ss_id;
    ts_hashmap_iterate(state->ss_map, find_first_ss_callback, &args);
    return ss;
}

// helpers end =================================================


//Orchestrates with an SS to create the file.
 
void handle_create(uint32_t client_id, int sock, MsgHeader* header, 
                   Payload_FileRequest* payload, NameServerState* state) {


    pthread_mutex_lock(&state->create_file_mutex);

    MsgHeader client_res_header = {0};
    MsgPayload client_res_payload = {0}; // <-- DECLARED
    client_res_header.version = PROTOCOL_VERSION;
    client_res_header.opcode = OP_NM_CREATE_RES; 
    client_res_header.client_id = client_id;
    client_res_header.length = sizeof(MsgHeader); // Success is header-only
    client_res_header.error = ERR_NONE;

    payload->filename[MAX_FILENAME_LEN - 1] = '\0';
    if (strlen(payload->filename) == 0) {
        pthread_mutex_unlock(&state->create_file_mutex); // <-- UNLOCK
        send_nm_error_response(sock, client_id, header->opcode, ERR_INVALID_COMMAND, "Filename cannot be empty");
        return;
    }
    
    if (ts_hashmap_get(state->file_metadata_map, payload->filename)){
        pthread_mutex_unlock(&state->create_file_mutex); // <-- UNLOCK
        safe_printf("NM: Client %u CREATE failed: '%s' already exists.\n", 
            client_id, payload->filename);
        send_nm_error_response(sock, client_id, header->opcode, ERR_FILE_EXISTS, "File already exists");
        return;
    }

    uint32_t selected_ss_id = 0;
    StorageServerInfo* ss = pick_ss_for_create(state, &selected_ss_id);
    
    if(ss == NULL){
        safe_printf("NM: Client %u CREATE failed: No Storage Servers available.\n", client_id);
        pthread_mutex_unlock(&state->create_file_mutex); // <-- UNLOCK
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "No Storage Servers available");
        return;
    }
    safe_printf("NM: Selected SS %u for new file creation.\n", selected_ss_id);
    
    safe_printf("NM: Opening temporary connection to SS %u at %s:%u\n", 
        ss->id, ss->ip, ss->client_port);

    int ss_sock;
    struct sockaddr_in ss_addr;

    if((ss_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("NM: handle_create socket");
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Internal Error (Socket)");
        return;
    }
    
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss->client_port);
    if(inet_pton(AF_INET, ss->ip, &ss_addr.sin_addr) <= 0) {
        perror("NM: handle_create inet_pton");
        close(ss_sock);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Internal Error (pton)");
        return;
    }
    
    if (connect(ss_sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        perror("NM: handle_create connect");
        close(ss_sock);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Cannot connect to Storage Server");
        return;
    }

    safe_printf("NM: Connected to SS. Sending OP_NM_SS_CREATE_REQ.\n");
        
    MsgHeader ss_header = {0};
    MsgPayload ss_payload = {0};
    
    ss_header.version = PROTOCOL_VERSION;
    ss_header.opcode = OP_NM_SS_CREATE_REQ;
    ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
    strncpy(ss_payload.file_req.filename, payload->filename, MAX_FILENAME_LEN - 1);
    
    if (send_message(ss_sock, &ss_header, &ss_payload) == -1) {
        safe_printf("NM: Failed to send CREATE command to SS %u\n", ss->id);
        close(ss_sock);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Failed to send command to SS");
        return;
    }
    
    if (recv_message(ss_sock, &ss_header, &ss_payload) <= 0) {
        safe_printf("NM: Failed to get response from SS %u (disconnected)\n", ss->id);
        close(ss_sock);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Storage Server disconnected unexpectedly");
        return;
    }
    
    close(ss_sock);

    if (ss_header.opcode != OP_SS_NM_CREATE_RES || ss_header.error != ERR_NONE) {
        safe_printf("NM: SS %u failed to create file (Error: %u)\n", ss->id, ss_header.error);
        pthread_mutex_unlock(&state->create_file_mutex); // <-- UNLOCK
        send_nm_error_response(sock, client_id, header->opcode, ss_header.error, "Storage Server failed to create file");
        return;
    }

    safe_printf("NM: SS %u ACK'd file creation. Updating metadata.\n", ss->id);
    
    char client_id_key[16];
    snprintf(client_id_key, 16, "%u", client_id);
    ClientInfo* creator = ts_hashmap_get(state->client_id_map, client_id_key);
    
    FileMetadata* meta = malloc(sizeof(FileMetadata));
    pthread_mutex_init(&meta->meta_lock, NULL);

    pthread_mutex_lock(&meta->meta_lock);

    strncpy(meta->filename, payload->filename, MAX_FILENAME_LEN - 1);
    meta->ss_id = selected_ss_id; 
    if(creator)
        strncpy(meta->owner_username, creator->username, MAX_USERNAME_LEN - 1);
    else
        strncpy(meta->owner_username, "unknown", MAX_USERNAME_LEN - 1);

    uint64_t now = (uint64_t)time(NULL);
    meta->file_size = 0;
    meta->created_at = now;
    meta->modified_at = now;
    meta->accessed_at = now;
    meta->access_list = ts_hashmap_create();
    char* owner_permission = strdup("RW");
    ts_hashmap_put(meta->access_list, strdup(creator->username), (void*)owner_permission);
    
    meta->pending_requests = ts_hashmap_create();
    
    pthread_mutex_unlock(&meta->meta_lock);
    
    
    ts_hashmap_put(state->file_metadata_map, meta->filename, meta);
    ts_hashmap_put(ss->file_list, meta->filename, NULL); 

    persistence_log_op("META,CREATE,%s,%s,%u,%llu",
                       meta->filename,
                       meta->owner_username,
                       meta->ss_id,
                       (unsigned long long)meta->created_at);


    // --- ATOMICITY FIX: Unlock after all state changes ---
    pthread_mutex_unlock(&state->create_file_mutex);
    safe_printf("NM: Sending final CREATE_RES to client %u\n", client_id);
    send_message(sock, &client_res_header, &client_res_payload);
}

/**
 * @brief Handles P1 redirect commands (READ, WRITE, STREAM, UNDO).
 * Finds the correct SS and sends a redirect packet to the client.
 */
void handle_redirect(uint32_t client_id, int sock, MsgHeader* header, 
                     Payload_FileRequest* payload, NameServerState* state) {

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0}; // <-- DECLARED
    res_header.version = PROTOCOL_VERSION;
    res_header.client_id = client_id;
    
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';

    // 2. Find the file's metadata
    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, payload->filename);
    if (meta == NULL) {
        safe_printf("NM: Client %u READ/WRITE failed: '%s' not found.\n",
            client_id, payload->filename);
        send_nm_error_response(sock, client_id, header->opcode, ERR_FILE_NOT_FOUND, "File not found");
        return;
    }

    pthread_mutex_lock(&meta->meta_lock);

    time_t now = time(NULL);
    persistence_log_op("META,SET_LAST_ACCESSED,%s,%ld\n", meta->filename, now);
    meta->accessed_at = now;

    pthread_mutex_unlock(&meta->meta_lock);


    // 3. TODO: Check permissions (P2)
    
    // 4. Find the Storage Server for this file
    char ss_key[16];
    snprintf(ss_key, 16, "%u", meta->ss_id);
    StorageServerInfo* ss = ts_hashmap_get(state->ss_map, ss_key);

    if (ss == NULL) {
        safe_printf("NM: File '%s' metadata points to dead SS %u.\n",
            payload->filename, meta->ss_id);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "Storage Server for file is offline");
        return;
    }

    // 5. Build the appropriate redirect response
    switch(header->opcode) {
        
        case OP_CLIENT_READ_REQ:   
            res_header.opcode = OP_NM_READ_RES;   
            meta->accessed_at = (uint64_t)time(NULL);
            break;
        case OP_CLIENT_WRITE_REQ:
            res_header.opcode = OP_NM_WRITE_RES;  
            meta->accessed_at = (uint64_t)time(NULL);
            break;
        case OP_CLIENT_STREAM_REQ:
            res_header.opcode = OP_NM_STREAM_RES;
            meta->accessed_at = (uint64_t)time(NULL);
            break;        
        case OP_CLIENT_UNDO_REQ:
            res_header.opcode = OP_NM_UNDO_RES;
            // should undo mark last accessed? TODO CHECK
            //meta->accessed_at = (uint64_t)time(NULL);
            break;
        case OP_CLIENT_REDO_REQ: // <-- ADD THIS
            res_header.opcode = OP_NM_REDO_RES;
            // A redo is also a modification
            //meta->accessed_at = (uint64_t)time(NULL);
            break;
        default:
            send_nm_error_response(sock, client_id, header->opcode, ERR_UNKNOWN, "Invalid redirect operation");
            return;
    }

    res_header.length = sizeof(MsgHeader) + sizeof(Payload_SSRedirect);
    res_header.error = ERR_NONE;

    // 6. Populate the redirect payload
    strncpy(res_payload.redirect.ss_ip, ss->ip, MAX_IP_LEN - 1);
    res_payload.redirect.ss_port = ss->client_port;

    safe_printf("NM: Redirecting client %u for file '%s' to SS %u at %s:%u\n",
        client_id, payload->filename, meta->ss_id, ss->ip, ss->client_port);

    // 7. Send the redirect packet
    if (send_message(sock, &res_header, &res_payload) == -1) { // <-- USES DECLARED VAR
        safe_printf("NM: Failed to send redirect to client %u\n", client_id);
    }
}

static int send_onetime_ss_command(StorageServerInfo* ss, MsgHeader* header, MsgPayload* payload) {
    int ss_sock;
    struct sockaddr_in ss_addr;

    if ((ss_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("NM: socket (onetime)"); return -1;
    }

    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss->client_port); // Connect to the SS's *NM-facing* port
    if(inet_pton(AF_INET, ss->ip, &ss_addr.sin_addr) <= 0) {
        perror("NM: inet_pton (onetime)"); close(ss_sock); return -1;
    }
    
    if (connect(ss_sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        perror("NM: connect (onetime)"); close(ss_sock); return -1;
    }

    // Send the command
    if (send_message(ss_sock, header, payload) == -1) {
        safe_printf("NM: Failed to send onetime command to SS %u\n", ss->id);
        close(ss_sock); return -1;
    }

    // Wait for the ACK
    MsgHeader res_header;
    MsgPayload res_payload;
    if (recv_message(ss_sock, &res_header, &res_payload) <= 0) { 
        safe_printf("NM: Did not receive ACK from SS %u\n", ss->id);
        close(ss_sock); return -1;
    }
    
    close(ss_sock);
    
    if (res_header.error != ERR_NONE) {
        safe_printf("NM: SS %u returned error %d for onetime command\n", ss->id, res_header.error);
        return -1;
    }
    return 0; // Success
}

void handle_delete(uint32_t client_id, int sock, 
                          Payload_FileRequest* payload, NameServerState* state) {

    // 1. Get meta and user
    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename); 
    const char* username = get_username_from_id(state, client_id);

    // 2. Check for NULLs
    if (meta == NULL) {
        send_nm_error(sock, ERR_FILE_NOT_FOUND, "File not found.");
        return;
    }

    // 3. --- ACCESS CHECK ---
    // Only the file owner can delete it.
    if (strcmp(username, meta->owner_username) != 0) {
        send_nm_error(sock, ERR_ACCESS_DENIED, "Access denied: Only the file owner can delete this file.");
        return;
    }

    // --- FIX: MOVED LOGIC TO AFTER SS COMMAND ---
    // 4. --- FORWARD TO SS ---

    char ss_id_key[16];
    snprintf(ss_id_key, 16, "%u", meta->ss_id);
    StorageServerInfo* ss_info = (StorageServerInfo*)ts_hashmap_get(state->ss_map, ss_id_key);

    if (ss_info) {
        // Build the delete packet
        MsgHeader ss_header = {0};
        ss_header.version = PROTOCOL_VERSION;
        ss_header.opcode = OP_NM_SS_DELETE_REQ;
        ss_header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);

        MsgPayload ss_payload = {0};
        memcpy(&ss_payload.file_req, payload, sizeof(Payload_FileRequest));

        // --- This call is BLOCKING. It waits for the SS to finish. ---
        if (send_onetime_ss_command(ss_info, &ss_header, &ss_payload) != 0) {
            safe_printf("NM: Failed to delete file on SS %u. Aborting delete.\n", meta->ss_id);
            // --- FIX: If SS fails, tell the client and DO NOT delete metadata ---
            send_nm_error(sock, ERR_SS_DOWN, "Storage server failed to confirm deletion. Please try again.");
            return;
        }
    } else {
        safe_printf("NM: SS %u not found. File is orphaned. Removing metadata entry only.\n", meta->ss_id);
        // If SS is down, we allow the metadata to be cleaned up.
    }

    // 5. --- LOGGING (Write-Ahead) ---
    // Only log *after* the SS has confirmed deletion (or is down)
    persistence_log_op("META,DELETE,%s\n", payload->filename);

    // 6. --- IN-MEMORY UPDATE ---
    // Now it is safe to remove the metadata
    void* old_meta = ts_hashmap_remove(state->file_metadata_map, payload->filename);
    lru_cache_remove(state->file_cache, payload->filename);
    if (old_meta) {
        free_file_metadata(old_meta);
    }

    // 7. --- Send Success to Client ---
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_DELETE_RES; 
    res_header.length = sizeof(MsgHeader);
    res_header.error = ERR_NONE;
    send_message(sock, &res_header, NULL);
}


/**
 * @brief Handles an SS telling us it has a file.
 * This populates the NM's file_metadata_map on SS startup.
 */
void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_SSSyncFile* payload, NameServerState* state) {
    
    // Sanitize filename
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';
    if(strlen(payload->filename) == 0)
        return;

    // Check if we *already* know about this file
    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, payload->filename);
    
    if (meta) {
        if (meta->ss_id == 0) {
            // This file was orphaned. This SS is now claiming it.
            safe_printf("NM: SS %u claiming orphaned file '%s'\n", 
                ss_id, payload->filename);
        }

        // We know this file. Is it on the right SS?
        else if (meta->ss_id == ss_id) {
            safe_printf("NM: SS %u re-sync'd file '%s'. (OK)\n", ss_id, payload->filename);
        /*    
            meta->file_size = payload->file_size;
            meta->accessed_at = (uint64_t)time(NULL);
            
            char ss_key[16];
            snprintf(ss_key, 16, "%u", ss_id);
            StorageServerInfo* ss_info = ts_hashmap_get(state->ss_map, ss_key);

            if (ss_info) {
                // 4. Add this filename to the SS's *local* file_list
                ts_hashmap_put(ss_info->file_list, payload->filename, (void*)1);
            } else {
                safe_printf("NM: CRITICAL: Could not find SS %u in ss_map during sync.\n", ss_id);
            }
        */
        }
        else{
            // This is a file conflict. We have a problem.
            safe_printf("NM: SS %u orphaned file '%s' in last session!, SS %u now owns it\n",
                meta->ss_id, payload->filename, ss_id);
        }

        pthread_mutex_lock(&meta->meta_lock);
        meta->ss_id = ss_id;
        meta->file_size = payload->file_size;
        //meta->accessed_at = (uint64_t)time(NULL);
        pthread_mutex_unlock(&meta->meta_lock);

    }
    
    else {
        // New file we've never seen. Add it.
        safe_printf("NM: SS %u sync'd new file '%s'. Adding to metadata.\n",
            ss_id, payload->filename);
        
        FileMetadata* new_meta = malloc(sizeof(FileMetadata));
        
        pthread_mutex_init(&new_meta->meta_lock, NULL);
        pthread_mutex_lock(&new_meta->meta_lock);

        strncpy(new_meta->filename, payload->filename, MAX_FILENAME_LEN - 1);
        new_meta->ss_id = ss_id;
        strncpy(new_meta->owner_username, "unregistered", MAX_USERNAME_LEN - 1);
        
        new_meta->file_size = payload->file_size; 
        new_meta->created_at = 0; // We don't have this info
        new_meta->modified_at = 0; // We don't have this info
        new_meta->accessed_at = 0; // Set to "now"
        new_meta->access_list = ts_hashmap_create(); // Initialize ACL
        char* owner_permission = strdup("R");
        ts_hashmap_put(new_meta->access_list, "everyone" , (void*)owner_permission);
        owner_permission = strdup("RW");
        ts_hashmap_put(new_meta->access_list, "unregistered" , (void*)owner_permission);
        
        new_meta->pending_requests = ts_hashmap_create();
        
        pthread_mutex_unlock(&new_meta->meta_lock);
        
        ts_hashmap_put(state->file_metadata_map, new_meta->filename, new_meta);
    
    }
    
    char ss_key[16];
    snprintf(ss_key, 16, "%u", ss_id);
    StorageServerInfo* ss_info = ts_hashmap_get(state->ss_map, ss_key);

    if (ss_info) {
        // 4. Add this filename to the SS's *local* file_list
        //    This is what handle_disconnect iterates over.
        //    We can use (void*)1 as a simple placeholder value.
        ts_hashmap_put(ss_info->file_list, payload->filename, (void*)1);
    } else {
        safe_printf("NM: CRITICAL: Could not find SS %u in ss_map during sync.\n", ss_id);
    }
}

