#include "nm_request_helpers2.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"
#include "nm_persistence.h"
#include <time.h>

typedef struct {    // needed for handle_info
    char* buffer;
    size_t  buffer_size;
    int* current_len;       // Pointer to the 'len' variable in the calling function
    int     count;       // Tracks how many entries we've added
} ACLIterateArgs;

typedef struct {
    char* buffer;           // The large response buffer
    size_t buffer_size;     // Total size of the buffer
    int* current_len;       // Pointer to the 'len' variable
    
    // Command info
    const char* username;   // The user requesting the view
    bool flag_a;            // Is -a set? 
    bool flag_l;            // Is -l set? 
    int file_count;         // How many files we've added
    NameServerState* state;
} ViewIterateArgs;

typedef struct {
    char* buffer;       // Pointer to the large buffer
    size_t current_len; // How much we've written
    size_t max_len;     // Total size (MAX_BUFFER_LEN)
} ListBuilder;

static void build_view_entry(const char* key, void* value, void* arg) {
    FileMetadata* meta = (FileMetadata*)value;
    ViewIterateArgs* args = (ViewIterateArgs*)arg;

    // 1. Filter out .bak files
    const char* ext = ".bak";
    size_t file_len = strlen(meta->filename);
    size_t ext_len = strlen(ext);
    if (file_len > ext_len && strcmp(meta->filename + file_len - ext_len, ext) == 0) {
        return; // Skip this file
    }

    bool is_online = false;
    char ss_id_key[16];
    snprintf(ss_id_key, 16, "%u", meta->ss_id);

    // 2. --- Access Check ---
    if (!args->flag_a) {
        // If not 'view -a', we MUST check permission
        if (!check_access(meta, args->username, PERM_READ)) {
            return; // Skip this file
        }
    }

    if (ts_hashmap_get(args->state->ss_map, ss_id_key) != NULL) { 
        is_online = true;
    }

    // 2. --- Lock to read metadata safely ---
    // We must lock to get a consistent view of the file's details
    if (is_online) {
        pthread_mutex_lock(&meta->meta_lock);
    }
    // 3. --- Format the output string ---
    char entry_buffer[1024]; // Buffer for this single line
    
    if (args->flag_l) {
        
        if(is_online){
            // Detailed view
            char time_str[64];
            if (meta->modified_at == 0) {
                snprintf(time_str, sizeof(time_str), "NA");
            } else {
                struct tm *tm_info = localtime((time_t*)&meta->modified_at);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
            }
            snprintf(entry_buffer, sizeof(entry_buffer),
                "│ %-20s │ %-8llu │ %-16s │ %-16s │\n",
                meta->filename,
                (unsigned long long)meta->file_size,
                meta->owner_username,
                time_str
            );
        }
        else{
            // Show offline for 'view -l' or 'view -al'
            snprintf(entry_buffer, sizeof(entry_buffer),
                "│ %-20s │ %-8s │ %-16s │ %-16s │\n",
                meta->filename, "offline", "offline", "offline");
        }
    } else {
        // Simple view
        snprintf(entry_buffer, sizeof(entry_buffer), "--> %s%s\n", 
            meta->filename, is_online ? "" : " (offline)");
    }

    // 4. --- Unlock ---
    pthread_mutex_unlock(&meta->meta_lock);

    // 5. --- Append to main buffer ---
    int entry_len = strlen(entry_buffer);
    if (*(args->current_len) + entry_len < (int)args->buffer_size - 1) {
        strcpy(args->buffer + *(args->current_len), entry_buffer);
        *(args->current_len) += entry_len;
        args->file_count++;
    }
}

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

static void append_acl_entry(const char* key, void* value, void* arg) {
    const char* username = key;
    const char* permission = (const char*)value;
    ACLIterateArgs* args = (ACLIterateArgs*)arg;

    if (*(args->current_len) >= (int)args->buffer_size - (MAX_USERNAME_LEN + 10)) {
        return;
    }

    const char* prefix = (args->count > 0) ? ", " : "";

    *(args->current_len) += snprintf(
        args->buffer + *(args->current_len), 
        args->buffer_size - *(args->current_len),
        "%s%s (%s)", 
        prefix, 
        username, 
        permission
    );

    args->count++;
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
}

static void format_timestamp(uint64_t ts, char* buf, size_t buf_len) {
    if (ts == 0) {
        snprintf(buf, buf_len, "N/A");
        return;
    }
    time_t raw_time = (time_t)ts;
    struct tm* time_info = localtime(&raw_time);
    strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S", time_info);
}

void handle_info(uint32_t client_id, int sock, 
                 Payload_FileRequest* payload, NameServerState* state) {

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.client_id = client_id;

    // 1. Find the file in the global metadata map
    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, payload->filename);

    if (meta == NULL) {
        safe_printf("NM: Client %u requested INFO for non-existent file '%s'\n", 
            client_id, payload->filename);
        
        res_header.opcode = OP_ERROR_RES;
        res_header.error = ERR_FILE_NOT_FOUND;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
        strncpy(res_payload.error.message, "File not found.", MAX_ERROR_MSG_LEN - 1);
        send_message(sock, &res_header, &res_payload);
        return;
    }

    // 2. File found. Get SS info (it might be offline)
    char ss_key[16];
    snprintf(ss_key, 16, "%u", meta->ss_id);
    StorageServerInfo* ss_info = ts_hashmap_get(state->ss_map, ss_key);
    
    // if info = access
    //meta->accessed_at = (uint64_t)time(NULL);

    char ss_location[MAX_IP_LEN + 32]; // Buffer for SS location string
    if (ss_info) {
        snprintf(ss_location, sizeof(ss_location), "Server %u at %s:%u",
            ss_info->id, ss_info->ip, ss_info->client_port);
    } else {
        snprintf(ss_location, sizeof(ss_location), "Storage Server %u (Offline)", meta->ss_id);
    }

    pthread_mutex_lock(&meta->meta_lock);
    
    // 3. Format Timestamps
    char created_buf[32], modified_buf[32], accessed_buf[32];
    format_timestamp(meta->created_at, created_buf, sizeof(created_buf));
    format_timestamp(meta->modified_at, modified_buf, sizeof(modified_buf));
    format_timestamp(meta->accessed_at, accessed_buf, sizeof(accessed_buf));

    // We'll build the full string and then copy it to the payload
    char response_buffer[MAX_BUFFER_LEN];
    int len = 0;
    
    // Use snprintf's return value to safely append
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "--> File: %s\n", meta->filename);
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "--> Owner: %s\n", meta->owner_username);
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "--> Size: %llu bytes\n", (unsigned long long)meta->file_size);
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "--> Created: %s\n", created_buf);
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "--> Last Modified: %s\n", modified_buf);
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "--> Last Accessed: %s\n", accessed_buf);
    
    // For Access: Just show owner for now. Iterating the map is a later task.
    len += snprintf(response_buffer + len, sizeof(response_buffer) - len, "--> Access: ");

    ACLIterateArgs iter_args;
    iter_args.buffer = response_buffer;
    iter_args.buffer_size = sizeof(response_buffer);
    iter_args.current_len = &len; // Pass the address of your 'len' variable
    iter_args.count = 0;          // Start with 0 entries printed

    // Iterate the hashmap, calling our callback for each entry
    ts_hashmap_iterate(meta->access_list, append_acl_entry, &iter_args);

    len += snprintf(response_buffer + len, sizeof(response_buffer) - len,
        "\n--> Location: %s\n", ss_location);

    pthread_mutex_unlock(&meta->meta_lock);

    // 5. Send the response
    res_header.opcode = OP_NM_INFO_RES;
    res_header.error = ERR_NONE;
    
    // Copy the final string to the payload buffer
    strncpy(res_payload.generic.buffer, response_buffer, MAX_BUFFER_LEN - 1);
    res_payload.generic.buffer[MAX_BUFFER_LEN - 1] = '\0';
    
    // Set the length to *only* what's needed
    res_header.length = sizeof(MsgHeader) + strlen(res_payload.generic.buffer) + 1;

    send_message(sock, &res_header, &res_payload);
}

/**
 * @brief Handles a client's request to VIEW files.
 */
void handle_view(uint32_t client_id, int sock, 
                        Payload_ClientViewReq* payload, NameServerState* state) {
    
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};

    // 1. Get user and flags
    const char* username = get_username_from_id(state, client_id);
    if (username == NULL) {
        send_nm_error(sock, ERR_UNKNOWN, "Internal server error: Client session not found.");
        return;
    }
    
    bool flag_a = (payload->flags & VIEW_FLAG_A); 
    bool flag_l = (payload->flags & VIEW_FLAG_L);

    // 2. Prepare the response buffer
    int len = 0;
    // We use the generic buffer from the payload
    memset(&res_payload.generic.buffer, 0, sizeof(res_payload.generic.buffer));

    // 3. Setup iterator arguments
    ViewIterateArgs args;
    args.buffer = res_payload.generic.buffer;
    args.buffer_size = sizeof(res_payload.generic.buffer);
    args.current_len = &len;
    args.username = username;
    args.flag_a = flag_a;
    args.flag_l = flag_l;
    args.file_count = 0;
    args.state = state;

    // 4. Add header if it's a list view
    if (flag_l) {
        len += snprintf(args.buffer + len, args.buffer_size - len,
            "┌───────────────────────────────────────────────────────────────────────┐\n"
            "│ Filename             │ Size     │ Owner            │ Last Modified    │\n"
            "└───────────────────────────────────────────────────────────────────────┘\n"
        );
    }

    // 5. --- Iterate the main file map ---
    // This locks all buckets, calls our callback, then unlocks
    ts_hashmap_iterate(state->file_metadata_map, build_view_entry, &args); 

    // 6. Add footer
    if (flag_l) {
        len += snprintf(args.buffer + len, args.buffer_size - len,
            "└───────────────────────────────────────────────────────────────────────┘\n"
        );
    }
    if (args.file_count == 0) {
        len += snprintf(args.buffer + len, args.buffer_size - len, "(No files to display)\n");
    }

    // 7. Send the response
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_VIEW_RES; 
    res_header.error = ERR_NONE;
    // Set the length to *only* what we've written
    res_header.length = sizeof(MsgHeader) + len;

    send_message(sock, &res_header, &res_payload); 
}

/**
 * @brief Helper to fetch file content from an SS.
 * @return A malloc'd buffer with the content, or NULL on failure.
 */
static char* get_ss_file_content(StorageServerInfo* ss, Payload_FileRequest* payload) {
    int ss_sock;
    struct sockaddr_in ss_addr;
    
    // 1. Connect to SS's client port
    if ((ss_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { return NULL; }
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss->client_port);
    if(inet_pton(AF_INET, ss->ip, &ss_addr.sin_addr) <= 0) { close(ss_sock); return NULL; }
    if (connect(ss_sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) { close(ss_sock); return NULL; }

    //safe_printf("DEBUG (NM): Connected to SS at %s:%u. Sending OP_NM_SS_INTERNAL_READ_REQ.\n", ss->ip, ss->client_port);

    // 2. Send the INTERNAL_READ request
    MsgHeader header = {0};
    MsgPayload ss_payload = {0};
    header.version = PROTOCOL_VERSION;
    header.opcode = OP_NM_SS_INTERNAL_READ_REQ;
    header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
    memcpy(&ss_payload.file_req, payload, sizeof(Payload_FileRequest));

    if (send_message(ss_sock, &header, &ss_payload) == -1){
        close(ss_sock); return NULL;
    }

    //safe_printf("DEBUG (NM): Waiting for file chunks from SS...\n");

    // 3. Receive the file content (in chunks)
    char* full_buffer = NULL;
    size_t total_size = 0;
    
    while (recv_message(ss_sock, &header, &ss_payload) > 0){
        if (header.opcode != OP_SS_NM_INTERNAL_READ_RES || header.error != ERR_NONE) {
            if (full_buffer) free(full_buffer);
            close(ss_sock); return NULL;
        }
        Payload_FileDataChunk* chunk = &ss_payload.file_chunk;
        
        //safe_printf("DEBUG (NM): Received chunk. Data len: %u. Last chunk? %d\n",
        //    chunk->data_len, chunk->is_last_chunk);
        
        if (total_size == 0) { 
            full_buffer = (char*)malloc(chunk->file_size + 1); 
            if (!full_buffer) { close(ss_sock); return NULL; }
        }
        memcpy(full_buffer + total_size, chunk->data, chunk->data_len);
        total_size += chunk->data_len;
        if (chunk->is_last_chunk) break;
    }

    //safe_printf("DEBUG (NM): File receive loop finished. Total size: %zu\n", total_size);
    
    close(ss_sock);
    if (full_buffer) full_buffer[total_size] = '\0'; 
    return full_buffer;
}

/**
 * @brief Handles a client's request to EXEC a file.
 */
void handle_exec(uint32_t client_id, int sock, 
                 Payload_FileRequest* payload, NameServerState* state) {
    
    // 1. Get meta and user
    FileMetadata* meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename);
    const char* username = get_username_from_id(state, client_id);

    // 2. Checks (File exists, User exists)
    if (meta == NULL) { /*... send_nm_error and return ...*/ }
    if (username == NULL) { /*... send_nm_error and return ...*/ }

    // 3. --- ACCESS CHECK ---
    if (!check_access(meta, username, PERM_READ)) {
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_ACCESS_DENIED, "Access denied.");
        return;
    }

    //safe_printf("DEBUG (NM): Access check passed for EXEC.\n");

    // 4. --- Update Last Accessed ---
    // ... (lock, log SET_LAST_ACCESSED, update meta->accessed_at, unlock) ...

    // 5. --- Get File Content from SS ---
    char ss_id_key[16];
    snprintf(ss_id_key, 16, "%u", meta->ss_id);
    StorageServerInfo* ss_info = (StorageServerInfo*)ts_hashmap_get(state->ss_map, ss_id_key);

    if (ss_info == NULL){
        //safe_printf("DEBUG (NM): SS for file is offline.\n");
        return;
    }
    
    //safe_printf("DEBUG (NM): Calling get_ss_file_content from SS %u\n", ss_info->id);
    char* file_content = get_ss_file_content(ss_info, payload);
    if (file_content == NULL){
        //safe_printf("DEBUG (NM): get_ss_file_content returned NULL.\n");
        return;
    }

    const char* blocklist[] = {
        "sudo",           // Prevent privilege escalation
        "rm",         // Prevent recursive force delete
        "mkfs",           // Prevent formatting disks
        ":(){ :|:& };:", // Block classic fork bomb
        "dd if=/dev/zero", // Block disk wiping
        "chown",          // Block changing file ownership
        "chmod"           // Block changing file permissions
    };
    int num_blocked = sizeof(blocklist) / sizeof(blocklist[0]);

    for (int i = 0; i < num_blocked; i++) {
        if (strstr(file_content, blocklist[i]) != NULL) {
            safe_printf("NM: EXEC blocked for client %u. Reason: Dangerous pattern '%s'\n", 
                client_id, blocklist[i]);
            
            send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_DANGEROUS_COMMAND, 
                "Execution blocked: Script contains a dangerous or restricted command.");
            
            free(file_content);
            return; // Stop immediately
        }
    }

    //safe_printf("DEBUG (NM): Received %zu bytes from SS. Executing...\n", strlen(file_content));

    // 6. --- Execute the content ---
    char tmp_filename[] = "/tmp/docs_exec_XXXXXX";
    int tmp_fd = mkstemp(tmp_filename);
    if (tmp_fd == -1) {
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_EXEC_FAILED, "Failed to create temporary script file.");
        free(file_content); return;
    }
    
    const char* safety_prefix = 
        "# Auto-generated safety limits by Docs++ NM\n"
        "ulimit -u 30  # Max 30 user processes (prevents fork bomb)\n"
        "ulimit -t 10  # Max 10 seconds of CPU time (prevents infinite loop)\n"
        "ulimit -f 2048 # Max 2MB file size creation\n\n";

    // Write the safety prefix first
    write(tmp_fd, safety_prefix, strlen(safety_prefix));
    // Then write the user's script content
    write(tmp_fd, file_content, strlen(file_content));

    close(tmp_fd);
    free(file_content);

    char exec_command[MAX_PATH_LEN + 4];
    snprintf(exec_command, sizeof(exec_command), "sh %s", tmp_filename);

    // 7. --- Stream output back to client ---
    FILE* pipe = popen(exec_command, "r");
    if (!pipe) { /*... send_nm_error, unlink(tmp_filename), return ...*/ }

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_CLIENT_EXEC_OUTPUT; 
    res_header.client_id = client_id;

    while (fgets(res_payload.generic.buffer, MAX_BUFFER_LEN, pipe)) { 
        res_header.length = sizeof(MsgHeader) + strlen(res_payload.generic.buffer);
        send_message(sock, &res_header, &res_payload); 
    }
    pclose(pipe);
    unlink(tmp_filename);

    //safe_printf("DEBUG (NM): Execution finished. Sending OP_NM_CLIENT_EXEC_END.\n");

    // 8. --- Send EXEC_END ---
    res_header.opcode = OP_NM_CLIENT_EXEC_END;
    res_header.length = sizeof(MsgHeader);
    send_message(sock, &res_header, NULL); 
}