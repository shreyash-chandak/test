#include "ss_file_ops.h" // <-- NEW
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h> // <-- NEW FOR DIRECTORY SCANNING

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
    
    if (pthread_rwlock_init(&new_lock_info->content_rw_lock, NULL) != 0) {
        safe_printf("SS: CRITICAL: rwlock_init failed\n");
        free(new_lock_info);
        return -1;
    }
    if (pthread_mutex_init(&new_lock_info->map_mutex, NULL) != 0) {
        safe_printf("SS: CRITICAL: mutex_init failed\n");
        pthread_rwlock_destroy(&new_lock_info->content_rw_lock);
        free(new_lock_info);
        return -1;
    }
    
    new_lock_info->sentence_locks = ts_hashmap_create();
    if (new_lock_info->sentence_locks == NULL) {
        safe_printf("SS: CRITICAL: ts_hashmap_create failed for sentence locks\n");
        pthread_rwlock_destroy(&new_lock_info->content_rw_lock);
        pthread_mutex_destroy(&new_lock_info->map_mutex);
        free(new_lock_info);
        return -1;
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
        res_header.error = ERR_FILE_NOT_FOUND;
        // --- We MUST use a real error payload for the client ---
        res_header.opcode = OP_ERROR_RES;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
        strncpy(res_payload.error.message, "File not found on SS.", MAX_ERROR_MSG_LEN -1);
        send_message(client_sock, &res_header, &res_payload);
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
        res_header.error = ERR_UNKNOWN;
        res_header.opcode = OP_ERROR_RES;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
        strncpy(res_payload.error.message, "Internal server error (lock).", MAX_ERROR_MSG_LEN -1);
        send_message(client_sock, &res_header, &res_payload);
        return;
    }
    safe_printf("SS %u: READ lock acquired.\n", state->ss_id);

    // 4. Open the file and get its size
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        safe_printf("SS %u: File '%s' found in map but not on disk.\n", state->ss_id, payload->filename);
        pthread_rwlock_unlock(&lock_info->content_rw_lock); // Release lock
        res_header.error = ERR_FILE_NOT_FOUND;
        res_header.opcode = OP_ERROR_RES;
        res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
        strncpy(res_payload.error.message, "File not found on SS (disk).", MAX_ERROR_MSG_LEN -1);
        send_message(client_sock, &res_header, &res_payload);
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

    // Scan the disk *before* connecting to the NM.
    scan_and_init_file_locks(state);

    safe_printf("SS state initialized. Data dir: %s\n", state->data_dir);
}