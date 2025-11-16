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

/**
 * @brief Helper to free a FileLockInfo struct.
 * This is the callback for the file_lock_map.
 */
void free_file_lock_info(void* val) {
    if (!val) return;
    FileLockInfo* info = (FileLockInfo*)val;
    
    pthread_rwlock_destroy(&info->content_rw_lock);
    pthread_mutex_destroy(&info->map_mutex);
    
    // TODO: The sentence_locks map will hold SentenceLock pointers
    // which also need to be freed. We'll need a
    // free_sentence_lock callback for this.
    ts_hashmap_destroy(info->sentence_locks, NULL); 
    
    free(info);
}

/**
 * @brief Helper function to create and init a new FileLockInfo.
 * Returns NULL on failure.
 */
static FileLockInfo* create_new_lock_info() {
    FileLockInfo* new_lock_info = malloc(sizeof(FileLockInfo));
    if (!new_lock_info) {
        safe_printf("SS: CRITICAL: malloc failed for FileLockInfo\n");
        return NULL;
    }
    
    if (pthread_rwlock_init(&new_lock_info->content_rw_lock, NULL) != 0) {
        safe_printf("SS: CRITICAL: rwlock_init failed\n");
        free(new_lock_info);
        return NULL;
    }
    if (pthread_mutex_init(&new_lock_info->map_mutex, NULL) != 0) {
        safe_printf("SS: CRITICAL: mutex_init failed\n");
        pthread_rwlock_destroy(&new_lock_info->content_rw_lock);
        free(new_lock_info);
        return NULL;
    }
    
    new_lock_info->sentence_locks = ts_hashmap_create();
    if (new_lock_info->sentence_locks == NULL) {
        safe_printf("SS: CRITICAL: ts_hashmap_create failed for sentence locks\n");
        pthread_rwlock_destroy(&new_lock_info->content_rw_lock);
        pthread_mutex_destroy(&new_lock_info->map_mutex);
        free(new_lock_info);
        return NULL;
    }
    return new_lock_info;
}

void handle_ss_stream(StorageServerState* state, int client_sock, Payload_FileRequest* payload) {
    
    // 1. Find the file's lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) {
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS."); 
        close(client_sock);
        return;
    }

    // 2. Construct the full file path
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, payload->filename);

    // 3. Acquire the Read Lock (same as READ)
    safe_printf("SS %u: Acquiring READ lock for STREAM on '%s'\n", state->ss_id, payload->filename);
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock)."); 
        close(client_sock);
        return;
    }

    // 4. Open the file
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS (disk).");
        close(client_sock);
        return;
    }

    // 5. --- STREAMING LOOP ---
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_STREAM_DATA; 
    res_header.client_id = state->ss_id;
    res_header.length = sizeof(MsgHeader) + sizeof(Payload_StreamData);

    uint32_t seq = 0;
    char word_buffer[MAX_WRITE_CONTENT_LEN];
    int char_idx = 0;
    int c;

    while ((c = fgetc(file)) != EOF) {
        if (isspace(c)) {
            // It's whitespace (like ' ' or '\n').
            
            // 1. Send any word we've built so far.
            if (char_idx > 0) {
                word_buffer[char_idx] = '\0'; // Null-terminate
                strncpy(res_payload.stream_data.word, word_buffer, MAX_WRITE_CONTENT_LEN - 1);
                res_payload.stream_data.sequence_no = seq++; 
                
                if (send_message(client_sock, &res_header, &res_payload) == -1) { 
                    goto stream_end; // Client disconnected
                }
                char_idx = 0; // Reset buffer
            }
            
            // 2. Send this whitespace character as its own "word".
            word_buffer[0] = (char)c;
            word_buffer[1] = '\0';
            strncpy(res_payload.stream_data.word, word_buffer, MAX_WRITE_CONTENT_LEN - 1);
            res_payload.stream_data.sequence_no = seq++;
            if (send_message(client_sock, &res_header, &res_payload) == -1) { 
                goto stream_end; // Client disconnected
            }

        } else {
            // It's part of a word. Add it to the buffer.
            word_buffer[char_idx++] = (char)c;
            
            // If buffer is full, send it
            if (char_idx == MAX_WRITE_CONTENT_LEN - 1) {
                word_buffer[char_idx] = '\0'; // Null-terminate
                strncpy(res_payload.stream_data.word, word_buffer, MAX_WRITE_CONTENT_LEN - 1);
                res_payload.stream_data.sequence_no = seq++; 
                
                if (send_message(client_sock, &res_header, &res_payload) == -1) {
                    goto stream_end; // Client disconnected
                }
                char_idx = 0; // Reset buffer
            }
        }
    }
    
    // Send any remaining word after EOF
    if (char_idx > 0) {
        word_buffer[char_idx] = '\0'; // Null-terminate
        strncpy(res_payload.stream_data.word, word_buffer, MAX_WRITE_CONTENT_LEN - 1);
        res_payload.stream_data.sequence_no = seq++; 
        send_message(client_sock, &res_header, &res_payload);
    }

    stream_end:
    // 6. --- Send STREAM_END ---
    res_header.opcode = OP_SS_CLIENT_STREAM_END; 
    res_header.length = sizeof(MsgHeader);
    send_message(client_sock, &res_header, NULL); 

    // 7. Cleanup
    fclose(file);
    pthread_rwlock_unlock(&lock_info->content_rw_lock);
    close(client_sock);
    safe_printf("SS %u: STREAM complete for '%s'.\n", state->ss_id, payload->filename);
}

/**
 * @brief Handles an internal read request from the NM.
 * This is identical to handle_ss_read, but sends OP_SS_NM_INTERNAL_READ_RES.
 */
void handle_nm_internal_read(StorageServerState* state, int sock, Payload_FileRequest* payload) {
    // 1. Find lock info
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename); 
    if (lock_info == NULL) { /*... send_ss_error and return ...*/ }

    // 2. Construct file path
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, payload->filename);

    // 3. Acquire Read Lock
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) { /*... send_ss_error and return ...*/ }

    // 4. Open file
    FILE* file = fopen(file_path, "r");
    if (file == NULL) { /*... send_ss_error, unlock, and return ...*/ }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    //safe_printf("DEBUG (SS): File open. Size: %ld\n", file_size);
    // 5. Send file in chunks (identical to handle_ss_read)
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_NM_INTERNAL_READ_RES; // <-- The *only* difference
    res_header.client_id = state->ss_id;
    res_header.error = ERR_NONE;
    res_payload.file_chunk.file_size = (uint32_t)file_size;
    
    if (file_size == 0) {
        //safe_printf("DEBUG (SS): Sending 0-byte (empty) file chunk.\n");
        res_payload.file_chunk.data_len = 0;
        res_payload.file_chunk.is_last_chunk = 1;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
        send_message(sock, &res_header, &res_payload);
    } else {
        size_t bytes_sent = 0;
        while (bytes_sent < file_size) {
            size_t chunk_size = MAX_BUFFER_LEN;
            if (bytes_sent + chunk_size > file_size) {
                chunk_size = file_size - bytes_sent;
            }

            size_t bytes_read = fread(res_payload.file_chunk.data, 1, chunk_size, file);
            if (bytes_read != chunk_size) {
                //safe_printf("SS: File read error on '%s'.\n", payload->filename);
                send_ss_error(sock, ERR_READ_FAILED, "File read failure on SS.");
                break; // Stop loop
            }

            res_payload.file_chunk.data_len = (uint32_t)chunk_size;
            bytes_sent += chunk_size;
            res_payload.file_chunk.is_last_chunk = (bytes_sent == file_size);
            
            // --- CRITICAL DEBUG PRINT ---
            //safe_printf("DEBUG (SS): Sending chunk. Bytes: %u. Last chunk? %d\n", (uint32_t)chunk_size, res_payload.file_chunk.is_last_chunk);

            res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
            if (send_message(sock, &res_header, &res_payload) == -1) {
                //safe_printf("SS: Failed to send chunk to NM.\n");
                break; // Stop loop, client disconnected
            }
        }
    }

    // 6. Cleanup
    fclose(file);
    pthread_rwlock_unlock(&lock_info->content_rw_lock);
    close(sock); // This is a one-shot connection
}


/**
 * @brief Creates a new, empty file in the SS data directory
 * AND initializes its in-memory concurrency (lock) struct.
 *
 * @param state The SS state (to get data_dir).
 * @param filename The name of the file to create.
 * @return 0 on success, -1 on failure.
 */
int ss_create_file(StorageServerState* state, const char* filename) {
    // Construct the full path
    char file_path[MAX_PATH_LEN];

    // --- SAFER SNPRINTF ---
    int needed = snprintf(NULL, 0, "%s/%s", state->data_dir, filename);
    if (needed < 0 || (size_t)needed >= MAX_PATH_LEN) {
        safe_printf("SS: CRITICAL: Path for file '%s' is too long.\n", filename);
        return -1; 
    }
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, filename);
    // ----------------------

    safe_printf("SS: Attempting to create file at: %s\n", file_path);

    // Create the data_dir if it doesn't exist
    struct stat st = {0};
    if (stat(state->data_dir, &st) == -1) {
        if (mkdir(state->data_dir, 0700) == -1) {
            safe_printf("SS: Failed to create data directory: %s\n", state->data_dir);
            return -1;
        }
    }

    // Try to open the file with "w" (write), which creates it.
    FILE* file = fopen(file_path, "w");
    if (file == NULL) {
        perror("ss_create_file fopen");
        return -1;
    }
    fclose(file);

    // --- THIS IS THE FIX ---
    // We *must* create the lock info for this new file.
    safe_printf("SS: File created. Initializing in-memory lock struct...\n");
    FileLockInfo* new_lock_info = create_new_lock_info();
    if (new_lock_info == NULL) {
        return -1; // Error already printed
    }
    
    // Add it to the main map.
    // The key *must* be strdup'd or we need to guarantee 'filename' is stable.
    // For now, let's assume 'filename' (from the packet) is stable
    // enough for the NM, but here we should be careful.
    // Let's rely on the hashmap's strdup.
    ts_hashmap_put(state->file_lock_map, filename, new_lock_info);
    
    safe_printf("SS: Successfully created empty file: %s\n", filename);
    return 0;
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

// --- NEW FUNCTION: The core P1 READ logic ---
void handle_ss_read(StorageServerState* state, int client_sock, 
                    Payload_FileRequest* payload) {
    
    safe_printf("SS %u: READ request for '%s'\n", state->ss_id, payload->filename);

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_READ_RES; // This is a data packet
    res_header.client_id = state->ss_id;
    res_header.error = ERR_NONE;

    // 1. Find the lock info for this file
    FileLockInfo* lock_info = ts_hashmap_get(state->file_lock_map, payload->filename);
    if (lock_info == NULL) {
        safe_printf("SS %u: File '%s' not found in lock_map.\n", state->ss_id, payload->filename);
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(client_sock); // <-- FIX: close socket on error
        return;
    }

    // 2. Construct the full file path
    char file_path[MAX_PATH_LEN];
    int needed = snprintf(NULL, 0, "%s/%s", state->data_dir, payload->filename);
    if (needed < 0 || (size_t)needed >= MAX_PATH_LEN) {
        safe_printf("SS: CRITICAL: Path for file '%s' is too long.\n", payload->filename);
        res_header.error = ERR_UNKNOWN;
        res_header.opcode = OP_ERROR_RES;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
        strncpy(res_payload.error.message, "Internal server error.", MAX_ERROR_MSG_LEN -1);
        send_message(client_sock, &res_header, &res_payload);
        return;
    }
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, payload->filename);

    // 3. Acquire the *Read Lock*
    safe_printf("SS %u: Acquiring READ lock for '%s'\n", state->ss_id, payload->filename);
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) {
        safe_printf("SS %u: Failed to get READ lock.\n", state->ss_id);
        send_ss_error(client_sock, ERR_UNKNOWN, "Internal server error (lock).");
        close(client_sock); // <-- FIX: close socket on error
        return;
    }
    safe_printf("SS %u: READ lock acquired.\n", state->ss_id);

    // 4. Open the file and get its size
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        safe_printf("SS %u: File '%s' found in map but not on disk.\n", state->ss_id, payload->filename);
        pthread_rwlock_unlock(&lock_info->content_rw_lock); // Release lock
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS (disk).");
        close(client_sock); // <-- FIX: close socket on error
        return;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 5. Send the file in chunks
    res_payload.file_chunk.file_size = (uint32_t)file_size;
    size_t bytes_sent = 0;
    
    // --- THIS IS THE FIX for 0-byte files ---
    if (file_size == 0) {
        safe_printf("SS %u: Sending 0-byte (empty file) chunk for '%s'.\n", state->ss_id, payload->filename);
        res_payload.file_chunk.data_len = 0;
        res_payload.file_chunk.is_last_chunk = 1;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
        if (send_message(client_sock, &res_header, &res_payload) == -1) {
            safe_printf("SS %u: Failed to send 0-byte chunk to client.\n", state->ss_id);
        }
    } else {
        // --- This is the old loop, for files > 0 bytes ---
        while (bytes_sent < file_size) {
            size_t chunk_size = MAX_BUFFER_LEN;
            if (bytes_sent + chunk_size > file_size) {
                chunk_size = file_size - bytes_sent;
            }

            size_t bytes_read = fread(res_payload.file_chunk.data, 1, chunk_size, file);
            if (bytes_read != chunk_size) {
                safe_printf("SS %u: File read error on '%s'.\n", state->ss_id, payload->filename);
                // We send an *error packet*, not just a header
                res_header.error = ERR_READ_FAILED;
                res_header.opcode = OP_ERROR_RES;
                res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
                strncpy(res_payload.error.message, "File read failure on SS.", MAX_ERROR_MSG_LEN -1);
                send_message(client_sock, &res_header, &res_payload);
                break; // Stop loop
            }

            res_payload.file_chunk.data_len = (uint32_t)chunk_size;
            bytes_sent += chunk_size;
            res_payload.file_chunk.is_last_chunk = (bytes_sent == file_size);
            
            res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);

            if (send_message(client_sock, &res_header, &res_payload) == -1) {
                safe_printf("SS %u: Failed to send chunk to client.\n", state->ss_id);
                break; // Stop loop, client disconnected
            }

            res_payload.file_chunk.file_size = 0; 
        }
    }

    // 6. Cleanup
    fclose(file);
    pthread_rwlock_unlock(&lock_info->content_rw_lock);
    safe_printf("SS %u: READ complete. Releasing lock for '%s'.\n", state->ss_id, payload->filename);
    // --- CRITICAL FIX ---
    // This handler is now responsible for closing the socket.
    close(client_sock);
}

void handle_nm_ss_delete(StorageServerState* state, int sock, Payload_FileRequest* payload) {
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.client_id = state->ss_id;
    res_header.error = ERR_NONE;
    res_header.opcode = OP_SS_NM_DELETE_RES;
    res_header.length = sizeof(MsgHeader);

    char final_path[MAX_PATH_LEN];
    char backup_path[MAX_PATH_LEN + 4];
    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);

    // 1. Find the lock info for this file
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename);

    if (lock_info == NULL) {
        // File not in map, but we'll try to delete from disk anyway
        remove(final_path);
        remove(backup_path);
        safe_printf("SS %u: Deleted file '%s' (no lock info found).\n", state->ss_id, payload->filename);
        send_message(sock, &res_header, NULL); 
        close(sock);
        return;
    }

    // --- NEW LOCK CHECKS ---

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
    // We use trylock so it fails immediately if a lock is held.
    if (pthread_rwlock_trywrlock(&lock_info->content_rw_lock) != 0) {
        safe_printf("SS %u: DELETE for '%s' failed: File is busy (read/stream).\n", state->ss_id, payload->filename);
        send_ss_error(sock, ERR_FILE_LOCKED, "Cannot delete: File is currently being read or streamed.");
        close(sock);
        return;
    }

    // --- END LOCK CHECKS ---

    // 4. If we are here, we have the write lock and no sentences are locked.
    // It is safe to delete.
    
    // Delete the main file and the backup file
    remove(final_path);
    remove(backup_path);
    
    // Release the lock we just took
    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    // 5. Remove the lock info from the map
    void* old_lock_info = ts_hashmap_remove(state->file_lock_map, payload->filename);
    if (old_lock_info) {
        // This will destroy the rwlock, map_mutex, and the sentence_locks hashmap
        free_file_lock_info(old_lock_info);
    }

    safe_printf("SS %u: Deleted file '%s' per NM request.\n", state->ss_id, payload->filename);

    // 6. Send ACK to NM and close connection
    send_message(sock, &res_header, NULL); 
    close(sock);
}

// --- NEW: Helper for CREATE (moved from ss_handler.c) ---
void handle_nm_ss_create(StorageServerState* state, int sock, Payload_FileRequest* payload) {
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.client_id = state->ss_id;
    res_header.error = ERR_NONE;
    res_header.opcode = OP_SS_NM_CREATE_RES;
    res_header.length = sizeof(MsgHeader);

    if (ss_create_file(state, payload->filename) == -1) {
        safe_printf("SS %u: Failed to create file '%s'\n", 
            state->ss_id, payload->filename);
        res_header.error = ERR_UNKNOWN;
    } else {
        safe_printf("SS %u: Successfully created '%s', sending ACK to NM\n", 
            state->ss_id, payload->filename);
    }
    
    send_message(sock, &res_header, &res_payload);
    close(sock); // This is a one-shot command
}

static void scan_and_init_file_locks(StorageServerState* state) {
    safe_printf("SS: Scanning data_dir '%s' for existing files...\n", state->data_dir);
    DIR* d;
    struct dirent* dir;
    d = opendir(state->data_dir);
    if (!d) {
        safe_printf("SS: No data_dir found. Will create one on first CREATE.\n");
        return;
    }
    
    int count = 0;
    while ((dir = readdir(d)) != NULL) {
        // Skip "." and ".."
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
            continue;
        }
        
        // We found a file. Create its lock struct.
        FileLockInfo* new_lock_info = create_new_lock_info();
        if (new_lock_info) {
            ts_hashmap_put(state->file_lock_map, dir->d_name, new_lock_info);
            count++;
        }
    }
    closedir(d);
    safe_printf("SS: Pre-loaded %d existing files into lock_map.\n", count);
}

// --- MOVED FROM ss_main.c ---
void init_ss_state(StorageServerState* state, const char* data_dir, 
                   const char* nm_ip, uint16_t nm_port, uint16_t client_port,
                   const char* public_ip) {

    strncpy(state->data_dir, data_dir, MAX_PATH_LEN - 1);
    state->data_dir[MAX_PATH_LEN - 1] = '\0';

    strncpy(state->nm_ip, nm_ip, MAX_IP_LEN - 1);
    state->nm_ip[MAX_IP_LEN - 1] = '\0';

    strncpy(state->public_ip, public_ip, MAX_IP_LEN - 1);
    state->public_ip[MAX_IP_LEN - 1] = '\0';

    state->nm_port = nm_port;
    state->client_port = client_port;
    state->nm_socket_fd = -1;
    state->ss_id = 0; // Not registered yet

    state->file_lock_map = ts_hashmap_create();
    state->active_write_sessions = ts_hashmap_create();

    // Scan the disk *before* connecting to the NM.
    scan_and_init_file_locks(state);

    safe_printf("SS state initialized. Data dir: %s\n", state->data_dir);
}