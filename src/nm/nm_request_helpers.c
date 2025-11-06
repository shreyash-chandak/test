#include "nm_request_helpers.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"

// --- NEW HELPER FUNCTION ---
/**
 * @brief Sends a standardized, payload-based error response to a client.
 * This is the *correct* way to send an error.
 */
static void send_nm_error_response(int sock, uint32_t client_id, OpCode original_opcode, 
                                   ErrorCode error, const char* message) {
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0}; // Will hold the error message
    
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_ERROR_RES; // This is the *correct* response opcode
    res_header.client_id = client_id;
    res_header.error = error;
    
    // --- THIS IS THE FIX ---
    // We *must* send a real payload so the client can parse it.
    res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
    strncpy(res_payload.error.message, message, MAX_ERROR_MSG_LEN - 1);
    res_payload.error.message[MAX_ERROR_MSG_LEN - 1] = '\0';
    // --- END FIX ---

    // We don't care if this send fails, we're already in an error state.
    send_message(sock, &res_header, &res_payload);
}
// --- END NEW HELPER ---


// --- Struct used for the `handle_list` iterator ---
typedef struct {
    char* buffer;       // Pointer to the large buffer
    size_t current_len; // How much we've written
    size_t max_len;     // Total size (MAX_BUFFER_LEN)
} ListBuilder;

/**
 * @brief The callback function for ts_hashmap_iterate.
 * Appends one username to the list buffer.
 */
static void append_username_callback(const char* key, void* value, void* arg) {
    ClientInfo* client = (ClientInfo*)value;
    ListBuilder* builder = (ListBuilder*)arg;
    
    int needed = snprintf(NULL, 0, "  - %s (%s)\n", 
                         client->username, 
                         client->is_active ? "Active" : "Inactive");
                         
    if (builder->current_len + needed < builder->max_len) {
        int written = snprintf(builder->buffer + builder->current_len, 
                               builder->max_len - builder->current_len,
                               "  - %s (%s)\n",
                               client->username,
                               client->is_active ? "Active" : "Inactive");
        
        if (written > 0) {
            builder->current_len += written;
        }
    }
}


/**
 * @brief Implementation of the LIST command.
 */
void handle_list(uint32_t client_id, int sock, MsgHeader* header, NameServerState* state) {
    
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0}; 
    
    ListBuilder builder;
    builder.buffer = res_payload.generic.buffer;
    builder.max_len = MAX_BUFFER_LEN;
    
    int written = snprintf(builder.buffer, builder.max_len, "Registered Users:\n");
    if (written < 0) { 
        send_nm_error_response(sock, client_id, OP_CLIENT_LIST_REQ, ERR_UNKNOWN, "Server error creating list");
        return; 
    }
    builder.current_len = written;

    ts_hashmap_iterate(state->client_username_map, append_username_callback, &builder);

    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_LIST_RES;
    res_header.client_id = client_id;
    res_header.error = ERR_NONE;
    res_header.length = sizeof(MsgHeader) + builder.current_len + 1; 
    builder.buffer[builder.current_len] = '\0';
    
    if (send_message(sock, &res_header, &res_payload) == -1) {
        safe_printf("NM: Failed to send LIST response to client %u\n", client_id);
    } else {
        safe_printf("NM: Sent LIST response to client %u\n", client_id);
    }
}


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

static StorageServerInfo* pick_ss_for_create(NameServerState* state, uint32_t* selected_ss_id) {
    StorageServerInfo* ss = NULL;
    FindSSArgs args;
    args.found_ss = &ss;
    args.ss_id = selected_ss_id;
    ts_hashmap_iterate(state->ss_map, find_first_ss_callback, &args);
    return ss;
}
// --- End Helpers ---


/**
 * @brief Implementation of the CREATE command.
 * Orchestrates with an SS to create the file.
 */
void handle_create(uint32_t client_id, int sock, MsgHeader* header, 
                   Payload_FileRequest* payload, NameServerState* state) {

    // --- Prep *SUCCESS* Response Header ---
    MsgHeader client_res_header = {0};
    MsgPayload client_res_payload = {0}; // <-- DECLARED
    client_res_header.version = PROTOCOL_VERSION;
    client_res_header.opcode = OP_NM_CREATE_RES; 
    client_res_header.client_id = client_id;
    client_res_header.length = sizeof(MsgHeader); // Success is header-only
    client_res_header.error = ERR_NONE;

    // --- FIX: All error paths now use the safe helper ---
    
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';
    if (strlen(payload->filename) == 0) {
        send_nm_error_response(sock, client_id, header->opcode, ERR_INVALID_COMMAND, "Filename cannot be empty");
        return;
    }
    
    if (ts_hashmap_get(state->file_metadata_map, payload->filename)) {
        safe_printf("NM: Client %u CREATE failed: '%s' already exists.\n", 
            client_id, payload->filename);
        send_nm_error_response(sock, client_id, header->opcode, ERR_FILE_EXISTS, "File already exists");
        return;
    }

    uint32_t selected_ss_id = 0;
    StorageServerInfo* ss = pick_ss_for_create(state, &selected_ss_id);
    
    if (ss == NULL) {
        safe_printf("NM: Client %u CREATE failed: No Storage Servers available.\n", client_id);
        send_nm_error_response(sock, client_id, header->opcode, ERR_SS_DOWN, "No Storage Servers available");
        return;
    }
    safe_printf("NM: Selected SS %u for new file creation.\n", selected_ss_id);
    
    safe_printf("NM: Opening temporary connection to SS %u at %s:%u\n", 
        ss->id, ss->ip, ss->client_port);

    int ss_sock;
    struct sockaddr_in ss_addr;

    if ((ss_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
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
        send_nm_error_response(sock, client_id, header->opcode, ss_header.error, "Storage Server failed to create file");
        return;
    }

    safe_printf("NM: SS %u ACK'd file creation. Updating metadata.\n", ss->id);
    
    char client_id_key[16];
    snprintf(client_id_key, 16, "%u", client_id);
    ClientInfo* creator = ts_hashmap_get(state->client_id_map, client_id_key);
    
    FileMetadata* meta = malloc(sizeof(FileMetadata));
    strncpy(meta->filename, payload->filename, MAX_FILENAME_LEN - 1);
    meta->ss_id = selected_ss_id; 
    if (creator) {
        strncpy(meta->owner_username, creator->username, MAX_USERNAME_LEN - 1);
    } else {
        strncpy(meta->owner_username, "unknown", MAX_USERNAME_LEN - 1);
    }
    
    ts_hashmap_put(state->file_metadata_map, meta->filename, meta);
    ts_hashmap_put(ss->file_list, meta->filename, NULL); 

    // --- Send final "OK" to client ---
    safe_printf("NM: Sending final CREATE_RES to client %u\n", client_id);
    send_message(sock, &client_res_header, &client_res_payload); // <-- USES DECLARED VAR
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
        case OP_CLIENT_READ_REQ:   res_header.opcode = OP_NM_READ_RES;   break;
        case OP_CLIENT_WRITE_REQ:  res_header.opcode = OP_NM_WRITE_RES;  break;
        case OP_CLIENT_STREAM_REQ: res_header.opcode = OP_NM_STREAM_RES; break;
        case OP_CLIENT_UNDO_REQ:   res_header.opcode = OP_NM_UNDO_RES;   break;
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


/**
 * @brief Handles an SS telling us it has a file.
 * This populates the NM's file_metadata_map on SS startup.
 */
void handle_ss_sync_file(uint32_t ss_id, MsgHeader* header, 
                         Payload_FileRequest* payload, NameServerState* state) {
    
    // Sanitize filename
    payload->filename[MAX_FILENAME_LEN - 1] = '\0';
    if (strlen(payload->filename) == 0) return;

    // Check if we *already* know about this file
    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, payload->filename);
    
    if (meta) {
        // We know this file. Is it on the right SS?
        if (meta->ss_id == ss_id) {
            safe_printf("NM: SS %u re-sync'd file '%s'. (OK)\n", ss_id, payload->filename);
        } else {
            // This is a file conflict. We have a problem.
            safe_printf("NM: CRITICAL: SS %u tried to sync file '%s', but SS %u already owns it!\n",
                ss_id, payload->filename, meta->ss_id);
            // TODO: Handle replication or conflict logic.
        }
    } else {
        // New file we've never seen. Add it.
        safe_printf("NM: SS %u sync'd new file '%s'. Adding to metadata.\n",
            ss_id, payload->filename);
            
        FileMetadata* new_meta = malloc(sizeof(FileMetadata));
        strncpy(new_meta->filename, payload->filename, MAX_FILENAME_LEN - 1);
        new_meta->ss_id = ss_id;
        
        // We don't know the owner.
        // TODO: The SS should probably store and send the owner.
        strncpy(new_meta->owner_username, "unknown", MAX_USERNAME_LEN - 1);
        
        ts_hashmap_put(state->file_metadata_map, new_meta->filename, new_meta);
    }
}