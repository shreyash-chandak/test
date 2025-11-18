#include "ss_file_ops.h"
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h> 
#include "ss_write_helpers.h" 

void handle_ss_checkpoint(StorageServerState* state, int client_sock, Payload_CheckpointRequest* payload) {
    char final_path[MAX_PATH_LEN];
    char checkpoint_path[MAX_PATH_LEN * 2];

    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
    snprintf(checkpoint_path, sizeof(checkpoint_path), "%s.%s", final_path, payload->tag);

    // 1. Find lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(client_sock); return;
    }

    // 2. Acquire a READ lock (prevent writes during copy)
    safe_printf("SS %u: Acquiring READ lock for CHECKPOINT on '%s'\n", state->ss_id, payload->filename);
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock); return;
    }

    // 3. Perform the copy
    if (copy_file(final_path, checkpoint_path) != 0) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        send_ss_error(client_sock, ERR_WRITE_FAILED, "Failed to create checkpoint file.");
        close(client_sock); return;
    }

    // 4. Release lock and send success
    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_CHECKPOINT_RES;
    res_header.length = sizeof(MsgHeader);
    send_message(client_sock, &res_header, NULL);

    safe_printf("SS %u: CHECKPOINT created for '%s' with tag '%s'.\n", state->ss_id, payload->filename, payload->tag);
    close(client_sock);
}

void handle_ss_revert(StorageServerState* state, int client_sock, Payload_CheckpointRequest* payload) {
    char final_path[MAX_PATH_LEN];
    char backup_path[MAX_PATH_LEN + 4];
    char checkpoint_path[MAX_PATH_LEN * 2];

    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);
    snprintf(checkpoint_path, sizeof(checkpoint_path), "%s.%s", final_path, payload->tag);

    // 1. Find lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) { 
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(client_sock); 
        return; 
    }

    // 2. Check if checkpoint file exists BEFORE locking
    struct stat st;
    if (stat(checkpoint_path, &st) != 0) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "Checkpoint tag not found.");
        close(client_sock); return;
    }

    // 3. Acquire a WRITE lock
    safe_printf("SS %u: Acquiring WRITE lock for REVERT on '%s'\n", state->ss_id, payload->filename);
    if (pthread_rwlock_wrlock(&lock_info->content_rw_lock) != 0) { 
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock); 
        return; 
    }

    // 4. Create undo backup: rename(final -> bak)
    if (rename(final_path, backup_path) != 0) {
        if (errno != ENOENT) { // Not having a file is fine, but other errors are bad
            pthread_rwlock_unlock(&lock_info->content_rw_lock);
            send_ss_error(client_sock, ERR_WRITE_FAILED, "Failed to create undo backup.");
            close(client_sock); return;
        }
    }

    // 5. Perform the revert: copy(checkpoint -> final)
    if (copy_file(checkpoint_path, final_path) != 0) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        send_ss_error(client_sock, ERR_WRITE_FAILED, "Failed to copy checkpoint to main file.");
        // Try to restore the backup
        rename(backup_path, final_path);
        close(client_sock); return;
    }

    // 6. Release lock
    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    // 7. Notify NM of the change (like UNDO)
    uint64_t new_file_size = (uint64_t)st.st_size;
    MsgHeader nm_header = {0};
    MsgPayload nm_payload = {0};
    nm_header.version = PROTOCOL_VERSION;
    nm_header.opcode = OP_SS_NM_REVERT_COMPLETE;
    nm_header.client_id = state->ss_id;
    nm_header.length = sizeof(MsgHeader) + sizeof(Payload_SSNMRevertComplete);
    strncpy(nm_payload.revert_complete.filename, payload->filename, MAX_FILENAME_LEN - 1);
    nm_payload.revert_complete.new_file_size = new_file_size;
    send_message(state->nm_socket_fd, &nm_header, &nm_payload); 

    // 8. Send success to client
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_REVERT_RES;
    res_header.length = sizeof(MsgHeader);
    send_message(client_sock, &res_header, NULL);

    safe_printf("SS %u: REVERT complete for '%s' to tag '%s'.\n", state->ss_id, payload->filename, payload->tag);
    close(client_sock);
}

void handle_ss_viewcheckpoint(StorageServerState* state, int client_sock, Payload_CheckpointRequest* payload) {
    // This is just handle_ss_read, but on a different file.
    // We can create a modified copy of handle_ss_read.

    char checkpoint_path[MAX_PATH_LEN * 2];
    snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/%s.%s", 
        state->data_dir, payload->filename, payload->tag);

    // 1. Find lock info for the *original* file
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "Original file not found.");
        close(client_sock); return;
    }

    // 2. Acquire a READ lock on the *original* file
    // This prevents REVERT from running while we're reading a checkpoint
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock); return;
    }

    // 3. Open the checkpoint file
    FILE* file = fopen(checkpoint_path, "r");
    if (file == NULL) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "Checkpoint tag not found.");
        close(client_sock); return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 4. Send the file in chunks (identical to handle_ss_read)
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_READ_RES; // Client expects this
    res_payload.file_chunk.file_size = (uint32_t)file_size;

    if (file_size == 0) {
        res_payload.file_chunk.data_len = 0;
        res_payload.file_chunk.is_last_chunk = 1;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
        send_message(client_sock, &res_header, &res_payload);
    } else {
        size_t bytes_sent = 0;
        while (bytes_sent < file_size) {
            size_t chunk_size = MAX_BUFFER_LEN;
            if (bytes_sent + chunk_size > file_size) {
                chunk_size = file_size - bytes_sent;
            }
            size_t bytes_read = fread(res_payload.file_chunk.data, 1, chunk_size, file);
            if (bytes_read != chunk_size) { break; /* read error */ }

            res_payload.file_chunk.data_len = (uint32_t)chunk_size;
            bytes_sent += chunk_size;
            res_payload.file_chunk.is_last_chunk = (bytes_sent == file_size);
            res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
            if (send_message(client_sock, &res_header, &res_payload) == -1) {
                break; // client disconnect
            }
        }
    }

    // 5. Cleanup
    fclose(file);
    pthread_rwlock_unlock(&lock_info->content_rw_lock);
    close(client_sock);
}

void handle_ss_listcheckpoints(StorageServerState* state, int client_sock, Payload_FileRequest* payload) {
    // 1. Find lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found.");
        close(client_sock); return;
    }

    // 2. Acquire READ lock
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock); return;
    }

    // 3. Scan directory
    char response_buffer[MAX_BUFFER_LEN] = {0};
    int len = 0;
    int count = 0;
    len += snprintf(response_buffer, sizeof(response_buffer), "Checkpoints for '%s':\n", payload->filename);

    DIR* d = opendir(state->data_dir);
    if (!d) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        send_ss_error(client_sock, ERR_UNKNOWN, "Cannot open data directory.");
        close(client_sock); return;
    }

    struct dirent* dir;
    size_t base_len = strlen(payload->filename);

    while ((dir = readdir(d)) != NULL) {
        // Check if it starts with the filename and a dot
        if (strncmp(dir->d_name, payload->filename, base_len) == 0 && dir->d_name[base_len] == '.') {
            // Get the tag part
            const char* tag = dir->d_name + base_len + 1;
            // Exclude the ".bak" and ".undoing" files
            if (strcmp(tag, "bak") != 0 && strcmp(tag, "undoing") != 0) {
                len += snprintf(response_buffer + len, sizeof(response_buffer) - len, "  - %s\n", tag);
                count++;
            }
        }
    }
    closedir(d);

    if (count == 0) {
        len += snprintf(response_buffer + len, sizeof(response_buffer) - len, "  (No checkpoints found)\n");
    }

    // 4. Release lock
    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    // 5. Send response
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_LISTCHECKPOINTS_RES;
    res_header.length = sizeof(MsgHeader) + len;
    memcpy(res_payload.generic.buffer, response_buffer, len);

    send_message(client_sock, &res_header, &res_payload);
    close(client_sock);
}
