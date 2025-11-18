#include "nm_request_helpers2.h"
#include "nm_request_helpers.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"
#include "nm_persistence.h"
#include <time.h>

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

    // 3. Receive the file content (in chunks)
    char* full_buffer = NULL;
    size_t total_size = 0;
    
    while (recv_message(ss_sock, &header, &ss_payload) > 0){
        if (header.opcode != OP_SS_NM_INTERNAL_READ_RES || header.error != ERR_NONE) {
            if (full_buffer) free(full_buffer);
            close(ss_sock); return NULL;
        }
        Payload_FileDataChunk* chunk = &ss_payload.file_chunk;\
        
        if (total_size == 0) { 
            full_buffer = (char*)malloc(chunk->file_size + 1); 
            if (!full_buffer) { close(ss_sock); return NULL; }
        }
        memcpy(full_buffer + total_size, chunk->data, chunk->data_len);
        total_size += chunk->data_len;
        if (chunk->is_last_chunk) break;
    }
    
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
    if (meta == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_FILE_NOT_FOUND, "File not found.");
        return;
    }
    if (username == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_UNKNOWN, "Internal server error: User not found.");
        return;
    }

    // 3. --- ACCESS CHECK ---
    if (!check_access(meta, username, PERM_READ)) {
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_ACCESS_DENIED, "Access denied.");
        return;
    }

    // 4. --- Update Last Accessed ---
    pthread_mutex_lock(&meta->meta_lock);
    time_t now = time(NULL);
    persistence_log_op("META,SET_LAST_ACCESSED,%s,%ld", meta->filename, (long)now);
    meta->accessed_at = (uint64_t)now;
    pthread_mutex_unlock(&meta->meta_lock);

    // 5. --- Get File Content from SS ---
    StorageServerInfo* ss_info = get_live_replica_ss(state, meta);

    if (ss_info == NULL){
        safe_printf("NM: EXEC failed for '%s': All replicas are offline.\n", payload->filename);
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_SS_DOWN, "File replicas are offline.");
        return;
    }
    
    char* file_content = get_ss_file_content(ss_info, payload);
    if (file_content == NULL){
        safe_printf("NM: EXEC failed: Could not retrieve content from SS %u.\n", ss_info->id);
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_SS_DOWN, "Failed to retrieve file content from Storage Server.");
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
    if (write(tmp_fd, safety_prefix, strlen(safety_prefix)) == -1) {
        // Handle write error
        close(tmp_fd); unlink(tmp_filename); free(file_content);
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_EXEC_FAILED, "Failed to write to temp file.");
        return;
    }
    // Then write the user's script content
    if (write(tmp_fd, file_content, strlen(file_content)) == -1) {
        // Handle write error
        close(tmp_fd); unlink(tmp_filename); free(file_content);
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_EXEC_FAILED, "Failed to write content to temp file.");
        return;
    }

    close(tmp_fd);
    free(file_content);

    char exec_command[MAX_PATH_LEN + 4];
    snprintf(exec_command, sizeof(exec_command), "sh %s", tmp_filename);

    // 7. --- Stream output back to client ---
    FILE* pipe = popen(exec_command, "r");
    if (!pipe) {
        safe_printf("NM: popen failed for EXEC command.\n");
        send_nm_error_response(sock, client_id, OP_CLIENT_EXEC_REQ, ERR_EXEC_FAILED, "Failed to initiate script execution.");
        unlink(tmp_filename); 
        return; 
    }

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_CLIENT_EXEC_OUTPUT; 
    res_header.client_id = client_id;
    res_header.error = ERR_NONE; // Ensure error is none

    while (fgets(res_payload.generic.buffer, MAX_BUFFER_LEN, pipe)) { 
        res_header.length = sizeof(MsgHeader) + strlen(res_payload.generic.buffer);
        if (send_message(sock, &res_header, &res_payload) == -1) {
            safe_printf("NM: Client disconnected during EXEC stream.\n");
            break; // Stop executing if client leaves
        }
    }
    pclose(pipe);
    unlink(tmp_filename);

    // 8. --- Send EXEC_END ---
    res_header.opcode = OP_NM_CLIENT_EXEC_END;
    res_header.length = sizeof(MsgHeader);
    send_message(sock, &res_header, NULL); 
}