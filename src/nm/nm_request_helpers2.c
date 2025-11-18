#include "nm_request_helpers2.h"
#include "nm_request_helpers.h"
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

    // --- 2. ACCESS CONTROL  ---
    if (!args->flag_a) {
        // This is a standard 'VIEW', not 'VIEW -a'.
        // We MUST check for read access.
        // check_access is defined in utils.c and declared in utils.h
        if (!check_access(meta, args->username, PERM_READ)) {
            return; // Skip this file, user does not have access
        }
    }

    // 3. Get SS Info (was step 2)
    StorageServerInfo* live_ss = get_live_replica_ss(args->state, meta);
    bool is_online = (live_ss != NULL);

    // 4. --- Lock to read metadata safely --- (was step 2)
    // We must lock to get a consistent view of the file's details
    if (is_online) {
        pthread_mutex_lock(&meta->meta_lock);
    }
    // 5. --- Format the output string --- (was step 3)
    char entry_buffer[1024]; // Buffer for this single line
    
    if (args->flag_l) {
        
        if(is_online){
            // ... (rest of formatting logic remains the same) ...
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

    // 6. --- Unlock --- (was step 4)
    pthread_mutex_unlock(&meta->meta_lock);

    // 7. --- Append to main buffer --- (was step 5)
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
    StorageServerInfo* ss_info = get_live_replica_ss(state, meta);
    
    // if info = access
    //meta->accessed_at = (uint64_t)time(NULL);

    char ss_location[MAX_IP_LEN + 32]; // Buffer for SS location string
    if (ss_info) {
        // We found a live replica
        snprintf(ss_location, sizeof(ss_location), "Server %u at %s:%u (Online)",
            ss_info->id, ss_info->ip, ss_info->client_port);
    } else {
        // Both replicas are offline
        snprintf(ss_location, sizeof(ss_location), "Servers %u, %u (Offline)", 
            meta->ss_replicas[0], meta->ss_replicas[1]);
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