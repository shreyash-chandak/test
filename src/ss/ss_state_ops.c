#include "ss_file_ops.h"
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h> 
#include "ss_write_helpers.h" // For send_ss_error

/**
 * @brief Iterator callback to check if any sentence lock is held.
 */
static void check_if_any_sentence_locked(const char* key, void* value, void* arg) {
    SentenceLock* sen_lock = (SentenceLock*)value;
    int* is_locked_flag = (int*)arg;

    // If the flag is already set, we can stop
    if (*is_locked_flag) return;

    // We check client_id. If it's not 0, a session is active.
    // This works because handle_ss_etirw and handle_ss_write_cleanup
    // now correctly reset it to 0.
    if (sen_lock->client_id != 0) {
        *is_locked_flag = 1;
    }
}

// Replace the old handle_nm_ss_delete with this new version

void handle_nm_ss_delete(StorageServerState* state, int sock, Payload_FileRequest* payload) {
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.client_id = state->ss_id;
    res_header.error = ERR_NONE;
    res_header.opcode = OP_SS_NM_DELETE_RES;
    res_header.length = sizeof(MsgHeader);

    // 1. Find the lock info for this file
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename);

    if (lock_info == NULL) {
        // File not in map, but we'll try to delete from disk anyway
        safe_printf("SS %u: Deleted file '%s' (no lock info found).\n", state->ss_id, payload->filename);
        // (Scan logic is below, so we just proceed)
    } else {

        // 2. Check for active WRITE sessions (Sentence Locks)
        int is_locked = 0;
        pthread_mutex_lock(&lock_info->map_mutex);
        ts_hashmap_iterate(lock_info->sentence_locks, check_if_any_sentence_locked, &is_locked);
        pthread_mutex_unlock(&lock_info->map_mutex);

        if (is_locked) {
            safe_printf("SS %u: DELETE for '%s' failed: File has active WRITE session.\n", state->ss_id, payload->filename);
            send_ss_error(sock, ERR_FILE_LOCKED, "Cannot delete: File is currently being written to.");
            close(sock);
            return;
        }

        // 3. Check for active READ/STREAM sessions (Read Lock)
        if (pthread_rwlock_trywrlock(&lock_info->content_rw_lock) != 0) {
            safe_printf("SS %u: DELETE for '%s' failed: File is busy (read/stream).\n", state->ss_id, payload->filename);
            send_ss_error(sock, ERR_FILE_LOCKED, "Cannot delete: File is currently being read or streamed.");
            close(sock);
            return;
        }
    }

    // 4. Scan the data directory and delete all associated files
    // (e.g., file.txt, file.txt.bak, file.txt.v1, file.txt.v2, etc.)
    
    safe_printf("SS %u: Deleting file '%s' and all associated checkpoints/backups.\n", state->ss_id, payload->filename);
    
    DIR* d = opendir(state->data_dir);
    if (d) {
        struct dirent* dir;
        size_t base_len = strlen(payload->filename);
        
        while ((dir = readdir(d)) != NULL) {
            // Check if the filename starts with the base filename
            if (strncmp(dir->d_name, payload->filename, base_len) == 0) {
                
                // Check if it's the file itself OR file.* (file.bak, file.v1, etc.)
                if (dir->d_name[base_len] == '\0' || dir->d_name[base_len] == '.') {
                    
                    char file_to_delete[MAX_PATH_LEN];
                    snprintf(file_to_delete, sizeof(file_to_delete), "%s/%s", state->data_dir, dir->d_name);
                    
                    safe_printf("SS %u: Removing associated file: %s\n", state->ss_id, dir->d_name);
                    remove(file_to_delete);
                }
            }
        }
        closedir(d);
    } else {
        // Fallback if opendir fails (shouldn't happen, but good to have)
        safe_printf("SS %u: Warning: Could not open data_dir to scan for checkpoints. Deleting base file and .bak only.\n", state->ss_id);
        char final_path[MAX_PATH_LEN];
        char backup_path[MAX_PATH_LEN + 4];
        snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
        snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);
        remove(final_path);
        remove(backup_path);
    }

    // 5. Release lock (if we took it)
    if (lock_info) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
    }

    // 6. Remove the lock info from the map
    void* old_lock_info = ts_hashmap_remove(state->file_lock_map, payload->filename);
    if (old_lock_info) {
        // This will destroy the rwlock, map_mutex, and the sentence_locks hashmap
        free_file_lock_info(old_lock_info);
    }

    safe_printf("SS %u: Deleted file '%s' per NM request.\n", state->ss_id, payload->filename);

    // 7. Send ACK to NM and close connection
    send_message(sock, &res_header, NULL); 
    close(sock);
}


void handle_ss_undo(StorageServerState* state, int client_sock, Payload_FileRequest* payload) {
    char final_path[MAX_PATH_LEN];
    char backup_path[MAX_PATH_LEN + 4];
    char temp_path[MAX_PATH_LEN + 10]; // For the 3-way swap

    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);
    snprintf(temp_path, sizeof(temp_path), "%s.undoing", final_path);

    // 1. Find the file's lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(client_sock);
        return;
    }

    // 2. Acquire the full file write lock (this is a major operation)
    safe_printf("SS %u: Acquiring WRLOCK for UNDO on '%s'\n", state->ss_id, payload->filename);
    if (pthread_rwlock_wrlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock);
        return;
    }

    // 3. Perform the 3-way swap:
    //    file.txt -> file.txt.undoing
    //    file.txt.bak -> file.txt
    //    file.txt.undoing -> file.txt.bak
    if (rename(final_path, temp_path) != 0) {
        perror("ss: undo rename 1");
        send_ss_error(client_sock, ERR_WRITE_FAILED, "UNDO failed (step 1).");
    } else if (rename(backup_path, final_path) != 0) {
        perror("ss: undo rename 2");
        rename(temp_path, final_path); // Try to restore
        send_ss_error(client_sock, ERR_WRITE_FAILED, "UNDO failed (step 2).");
    } else if (rename(temp_path, backup_path) != 0) {
        perror("ss: undo rename 3");
        // This is not fatal, but the backup is now named ".undoing"
        send_ss_error(client_sock, ERR_WRITE_FAILED, "UNDO complete, but backup rename failed.");
    }

    // 4. Release the lock
    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    // 5. Notify NM of the (likely) file size change
    struct stat st;
    uint64_t new_file_size = 0;
    if (stat(final_path, &st) == 0) new_file_size = (uint64_t)st.st_size;

    MsgHeader nm_header = {0};
    MsgPayload nm_payload = {0};
    nm_header.version = PROTOCOL_VERSION;
    nm_header.opcode = OP_SS_NM_UNDO_COMPLETE; // Re-use the write complete packet
    nm_header.client_id = state->ss_id;
    nm_header.length = sizeof(MsgHeader) + sizeof(Payload_SSNMWriteComplete);
    strncpy(nm_payload.write_complete.filename, payload->filename, MAX_FILENAME_LEN - 1);
    nm_payload.write_complete.new_file_size = new_file_size;
    
    send_message(state->nm_socket_fd, &nm_header, &nm_payload); 

    // 6. Send success ACK to client
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_UNDO_RES;
    res_header.length = sizeof(MsgHeader);
    res_header.error = ERR_NONE;
    send_message(client_sock, &res_header, NULL);

    safe_printf("SS %u: UNDO complete for '%s'.\n", state->ss_id, payload->filename);
    close(client_sock);
}

void handle_ss_redo(StorageServerState* state, int client_sock, Payload_FileRequest* payload) {
    char final_path[MAX_PATH_LEN];
    char backup_path[MAX_PATH_LEN + 4];
    char temp_path[MAX_PATH_LEN + 10]; // For the 3-way swap

    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);
    snprintf(temp_path, sizeof(temp_path), "%s.undoing", final_path);

    // 1. Find the file's lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(client_sock);
        return;
    }

    // 2. Acquire the full file write lock (this is a major operation)
    safe_printf("SS %u: Acquiring WRLOCK for UNDO on '%s'\n", state->ss_id, payload->filename);
    if (pthread_rwlock_wrlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock);
        return;
    }

    // 3. Perform the 3-way swap:
    //    file.txt -> file.txt.undoing
    //    file.txt.bak -> file.txt
    //    file.txt.undoing -> file.txt.bak
    if (rename(final_path, temp_path) != 0) {
        perror("ss: redo rename 1");
        send_ss_error(client_sock, ERR_WRITE_FAILED, "REDO failed (step 1).");
    } else if (rename(backup_path, final_path) != 0) {
        perror("ss: redo rename 2");
        rename(temp_path, final_path); // Try to restore
        send_ss_error(client_sock, ERR_WRITE_FAILED, "REDO failed (step 2).");
    } else if (rename(temp_path, backup_path) != 0) {
        perror("ss: redo rename 3");
        // This is not fatal, but the backup is now named ".undoing"
        send_ss_error(client_sock, ERR_WRITE_FAILED, "REDO complete, but backup rename failed.");
    }

    // 4. Release the lock
    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    // 5. Notify NM of the (likely) file size change
    struct stat st;
    uint64_t new_file_size = 0;
    if (stat(final_path, &st) == 0) new_file_size = (uint64_t)st.st_size;

    MsgHeader nm_header = {0};
    MsgPayload nm_payload = {0};
    nm_header.version = PROTOCOL_VERSION;
    nm_header.opcode = OP_SS_NM_REDO_COMPLETE; 
    nm_header.client_id = state->ss_id;
    nm_header.length = sizeof(MsgHeader) + sizeof(Payload_SSNMRedoComplete);
    strncpy(nm_payload.write_complete.filename, payload->filename, MAX_FILENAME_LEN - 1);
    nm_payload.write_complete.new_file_size = new_file_size;
    
    send_message(state->nm_socket_fd, &nm_header, &nm_payload); 

    // 6. Send success ACK to client
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_UNDO_RES;
    res_header.length = sizeof(MsgHeader);
    res_header.error = ERR_NONE;
    send_message(client_sock, &res_header, NULL);

    safe_printf("SS %u: REDO complete for '%s'.\n", state->ss_id, payload->filename);
    close(client_sock);
}
