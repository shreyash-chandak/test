#include "ss_file_ops.h"
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h> 
#include "ss_write_helpers.h" 

/**
 * @brief Helper to copy a file from src path to dst path.
 * @return 0 on success, -1 on failure.
 */
int copy_file(const char* src_path, const char* dst_path) {
    FILE* src = fopen(src_path, "rb");
    if (!src) return -1;

    FILE* dst = fopen(dst_path, "wb");
    if (!dst) {
        fclose(src);
        return -1;
    }

    char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes_read, dst) != bytes_read) {
            fclose(src);
            fclose(dst);
            return -1; // Write error
        }
    }

    fclose(src);
    fclose(dst);
    return 0; // Success
}

// --- Frees a SentenceLock struct ---
void free_sentence_lock(void* val) {
    if (!val) return;
    SentenceLock* lock = (SentenceLock*)val;
    pthread_mutex_destroy(&lock->mutex);
    free(lock);
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
    
    ts_hashmap_destroy(info->sentence_locks, free_sentence_lock); 
    
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
    if (lock_info == NULL) {
        send_ss_error(sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(sock); 
        return; 
    }

    // 2. Construct file path
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, payload->filename);

    // 3. Acquire Read Lock
    if (pthread_rwlock_rdlock(&lock_info->content_rw_lock) != 0) {
        send_ss_error(sock, ERR_UNKNOWN, "Internal SS lock error.");
        close(sock); 
        return; 
    }

    // 4. Open file
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        send_ss_error(sock, ERR_FILE_NOT_FOUND, "File missing on disk.");
        close(sock); 
        return; 
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 5. Send file in chunks (identical to handle_ss_read)
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_NM_INTERNAL_READ_RES; 
    res_header.client_id = state->ss_id;
    res_header.error = ERR_NONE;
    res_payload.file_chunk.file_size = (uint32_t)file_size;
    
    if (file_size == 0) {
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
                send_ss_error(sock, ERR_READ_FAILED, "File read failure on SS.");
                break; 
            }

            res_payload.file_chunk.data_len = (uint32_t)chunk_size;
            bytes_sent += chunk_size;
            res_payload.file_chunk.is_last_chunk = (bytes_sent == file_size);
            
            res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
            if (send_message(sock, &res_header, &res_payload) == -1) {
                break; 
            }
        }
    }

    // 6. Cleanup
    fclose(file);
    pthread_rwlock_unlock(&lock_info->content_rw_lock);
    close(sock); 
}


/**
 * @brief Creates a new, empty file in the SS data directory
 * AND initializes its in-memory concurrency (lock) struct.
 */
int ss_create_file(StorageServerState* state, const char* filename) {
    // Construct the full path
    char file_path[MAX_PATH_LEN];

    int needed = snprintf(NULL, 0, "%s/%s", state->data_dir, filename);
    if (needed < 0 || (size_t)needed >= MAX_PATH_LEN) {
        safe_printf("SS: CRITICAL: Path for file '%s' is too long.\n", filename);
        return -1; 
    }
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, filename);
    
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

    // We must create the lock info for this new file.
    safe_printf("SS: File created. Initializing in-memory lock struct...\n");
    FileLockInfo* new_lock_info = create_new_lock_info();
    if (new_lock_info == NULL) {
        return -1; // Error already printed
    }
    
    ts_hashmap_put(state->file_lock_map, filename, new_lock_info);
    
    safe_printf("SS: Successfully created empty file: %s\n", filename);
    return 0;
}

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
        close(client_sock); 
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
        close(client_sock); 
        return;
    }
    safe_printf("SS %u: READ lock acquired.\n", state->ss_id);

    // 4. Open the file and get its size
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        safe_printf("SS %u: File '%s' found in map but not on disk.\n", state->ss_id, payload->filename);
        pthread_rwlock_unlock(&lock_info->content_rw_lock); // Release lock
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS (disk).");
        close(client_sock); 
        return;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 5. Send the file in chunks
    res_payload.file_chunk.file_size = (uint32_t)file_size;
    size_t bytes_sent = 0;
    
    // --- Handle 0 Byte Files---
    if (file_size == 0) {
        safe_printf("SS %u: Sending 0-byte (empty file) chunk for '%s'.\n", state->ss_id, payload->filename);
        res_payload.file_chunk.data_len = 0;
        res_payload.file_chunk.is_last_chunk = 1;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_FileDataChunk);
        if (send_message(client_sock, &res_header, &res_payload) == -1) {
            safe_printf("SS %u: Failed to send 0-byte chunk to client.\n", state->ss_id);
        }
    } else {
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
    close(client_sock);
}

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


/**
 * @brief Handles a request from another SS to read a file for replication.
 * (Called on the PRIMARY SS)
 * This is identical to handle_ss_read, but for an SS-to-SS connection.
 */
void handle_ss_replicate_read(StorageServerState* state, int sock, Payload_FileRequest* payload) {
    safe_printf("SS %u: REPLICATE_READ request for '%s' from another SS.\n", state->ss_id, payload->filename);
    handle_ss_read(state, sock, payload);
}

/**
 * @brief Handles an async request from the NM to replicate a file.
 * (Called on the SECONDARY SS)
 */
void handle_nm_ss_replicate(StorageServerState* state, int nm_sock, Payload_ReplicateRequest* payload) {
    // 1. Close the connection to the NM. This is fire-and-forget.
    close(nm_sock);

    safe_printf("SS %u: Received REPLICATE command for '%s'. Connecting to Primary SS at %s:%u.\n",
        state->ss_id, payload->filename, payload->primary_ss_ip, payload->primary_ss_port);

    // 2. Connect to the Primary SS
    int primary_sock;
    struct sockaddr_in primary_addr;

    if ((primary_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { return; }
    primary_addr.sin_family = AF_INET;
    primary_addr.sin_port = htons(payload->primary_ss_port);
    if(inet_pton(AF_INET, payload->primary_ss_ip, &primary_addr.sin_addr) <= 0) {
        close(primary_sock); return;
    }
    if (connect(primary_sock, (struct sockaddr *)&primary_addr, sizeof(primary_addr)) < 0) {
        safe_printf("SS %u: Failed to connect to Primary SS for replication.\n", state->ss_id);
        close(primary_sock); return;
    }

    // 3. Send the REPLICATE_READ request to the Primary SS
    MsgHeader header = {0};
    MsgPayload ss_payload = {0};
    header.version = PROTOCOL_VERSION;
    header.opcode = OP_SS_SS_REPLICATE_READ_REQ;
    header.client_id = state->ss_id; // Identify ourselves
    header.length = sizeof(MsgHeader) + sizeof(Payload_FileRequest);
    strncpy(ss_payload.file_req.filename, payload->filename, MAX_FILENAME_LEN - 1);

    if (send_message(primary_sock, &header, &ss_payload) == -1) {
        close(primary_sock); return;
    }

    // 4. Receive the file and write it to a temporary file
    char temp_path[MAX_PATH_LEN];
    snprintf(temp_path, sizeof(temp_path), "%s/%s.replicating", state->data_dir, payload->filename);

    FILE* tmp_file = fopen(temp_path, "wb");
    if (tmp_file == NULL) {
        close(primary_sock); return;
    }

    while (recv_message(primary_sock, &header, &ss_payload) > 0) {
        if (header.opcode != OP_SS_CLIENT_READ_RES || header.error != ERR_NONE) {
            break; // Error from primary
        }
        fwrite(ss_payload.file_chunk.data, 1, ss_payload.file_chunk.data_len, tmp_file);
        if (ss_payload.file_chunk.is_last_chunk) {
            break; // Success
        }
    }
    fclose(tmp_file);
    close(primary_sock);

    // 5. Get the file's lock and atomically swap the file
    FileLockInfo* lock_info = (FileLockInfo*)ts_hashmap_get(state->file_lock_map, payload->filename);
    if (lock_info == NULL) {
         safe_printf("SS %u: CRITICAL: No lock info for file '%s' during replication.\n", state->ss_id, payload->filename);
         remove(temp_path);
         return;
    }

    char final_path[MAX_PATH_LEN];
    char backup_path[MAX_PATH_LEN + 4];
    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, payload->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);

    // Acquire WRLOCK to make this atomic
    pthread_rwlock_wrlock(&lock_info->content_rw_lock);

    rename(final_path, backup_path); // Create backup of our old version
    rename(temp_path, final_path);   // Move new version into place

    pthread_rwlock_unlock(&lock_info->content_rw_lock);

    safe_printf("SS %u: Successfully replicated '%s' from Primary SS.\n",
        state->ss_id, payload->filename);
}