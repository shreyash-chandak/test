#include "ss_write_helpers.h"
#include "ss_file_ops.h" 
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <errno.h>    
#include <ctype.h>    
#include <sys/stat.h> 
#include <dirent.h>   


/**
 * @brief Helper to send a simple SS-side error response.
 */
void send_ss_error(int sock, ErrorCode error, const char* message) {
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};
    
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_ERROR_RES;
    res_header.error = error;
    res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
    strncpy(res_payload.error.message, message, MAX_ERROR_MSG_LEN - 1);
    
    send_message(sock, &res_header, &res_payload);
}

/**
 * @brief Helper to free a WriteSession and its ops
 */
void free_write_session(WriteSession* session) {
    if (!session) return;
    WriteOp* op = session->operations;
    while(op) {
        WriteOp* next = op->next;
        free(op);
        op = next;
    }
    free(session);
}

/**
 * @brief Helper to find the SentenceLock (MUST be held by this client)
 */
static SentenceLock* get_held_sentence_lock(FileLockInfo* lock_info, uint32_t sen_index) {
    char sentence_key[16];
    snprintf(sentence_key, 16, "%u", sen_index);
    SentenceLock* sen_lock = ts_hashmap_get(lock_info->sentence_locks, sentence_key);
    return sen_lock;
}


void handle_ss_write_start(StorageServerState* state, int client_sock, 
                           uint32_t client_id, Payload_ClientSSWriteStart* payload,
                           WriteSession** out_session) {
    
    *out_session = NULL; // Default to failure
    safe_printf("SS %u: WRITE_START request for '%s' (sent %u) from client %u\n",
        state->ss_id, payload->filename, payload->sentence_index, client_id);

    // 1. Find the file's lock info
    FileLockInfo* lock_info = ts_hashmap_get(state->file_lock_map, payload->filename);
    if (lock_info == NULL) {
        safe_printf("SS %u: File '%s' not found.\n", state->ss_id, payload->filename);
        send_ss_error(client_sock, ERR_FILE_NOT_FOUND, "File not found on SS.");
        close(client_sock); 
        return;
    }

    // --- Validate sentence index *before* locking ---
    uint32_t sentence_count = get_sentence_count(state, payload->filename);\
    // Fail if index >= count,
    // UNLESS both index and count are 0 (which is a valid write to an empty file).
    if (payload->sentence_index > sentence_count) {
        safe_printf("SS %u: Client %u requested sentence %u, but file only has %u sentences.\n",
            state->ss_id, client_id, payload->sentence_index, sentence_count);
        send_ss_error(client_sock, ERR_SENTENCE_OUT_OF_BOUNDS, "Sentence index is out of bounds.");
        close(client_sock);
        return;
    }
    
    // 2. Find or create the sentence lock
    char sentence_key[16];
    snprintf(sentence_key, 16, "%u", payload->sentence_index);
    
    pthread_mutex_lock(&lock_info->map_mutex);
    
    SentenceLock* sen_lock = ts_hashmap_get(lock_info->sentence_locks, sentence_key);
    
    if (sen_lock == NULL) {
        safe_printf("SS %u: Creating new lock for sentence %u\n", state->ss_id, payload->sentence_index);
        sen_lock = malloc(sizeof(SentenceLock));
        pthread_mutex_init(&sen_lock->mutex, NULL);
        sen_lock->client_id = 0;
        sen_lock->lock_count = 0;
        ts_hashmap_put(lock_info->sentence_locks, sentence_key, sen_lock);
    }
    
    // 3. Try to acquire the sentence lock
    if (pthread_mutex_trylock(&sen_lock->mutex) != 0) {
        safe_printf("SS %u: Sentence %u is ALREADY LOCKED by client %u.\n",
            state->ss_id, payload->sentence_index, sen_lock->client_id);
            
        pthread_mutex_unlock(&lock_info->map_mutex); 
        send_ss_error(client_sock, ERR_SENTENCE_LOCKED, "Sentence is locked by another user.");
        close(client_sock); 
        return;
    }
    
    // --- WE HAVE THE LOCK ---
    safe_printf("SS %u: Client %u ACQUIRED lock for sentence %u\n",
        state->ss_id, client_id, payload->sentence_index);
        
    sen_lock->client_id = client_id;
    sen_lock->lock_count = 1;
    pthread_mutex_unlock(&lock_info->map_mutex);

    // 4. Create the new WriteSession
    WriteSession* session = malloc(sizeof(WriteSession));
    session->client_id = client_id;
    strncpy(session->filename, payload->filename, MAX_FILENAME_LEN - 1);
    session->sentence_index = payload->sentence_index;
    session->operations = NULL;
    
    *out_session = session;
    
    // 6. Send "OK" back to the client
    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_SS_CLIENT_WRITE_START_RES;
    res_header.error = ERR_NONE;
    res_header.length = sizeof(MsgHeader);
    
    if (send_message(client_sock, &res_header, NULL) == -1) {
        safe_printf("SS %u: Failed to send WRITE_START_RES to client %u\n", state->ss_id, client_id);
        *out_session = NULL; 
    }
    
    safe_printf("SS %u: WRITE session started for client %u on socket %d\n",
        state->ss_id, client_id, client_sock);
}

void handle_ss_write_data(WriteSession* session, Payload_ClientSSWriteData* payload) {
    if (!session) return;
    
    safe_printf("SS: Buffering WRITE_DATA for sent %u, word %u\n",
        session->sentence_index, payload->word_index);
        
    WriteOp* new_op = malloc(sizeof(WriteOp));
    new_op->word_index = payload->word_index;
    strncpy(new_op->content, payload->content, MAX_WRITE_CONTENT_LEN - 1);
    new_op->content[MAX_WRITE_CONTENT_LEN - 1] = '\0';
    
    new_op->next = session->operations;
    session->operations = new_op;
}

/**
 * @brief Handles a client's ETIRW (commit) request.
 */
int handle_ss_etirw(StorageServerState* state, WriteSession* session) {
    if (!session) return -1;
    
    safe_printf("SS %u: ETIRW received for '%s' (sent %u)\n",
        state->ss_id, session->filename, session->sentence_index);

    // 1. Get file paths
    char final_path[MAX_PATH_LEN];
    char backup_path[MAX_PATH_LEN + 4]; // for ".bak"
    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, session->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);

    // 2. Find the lock structs
    FileLockInfo* lock_info = ts_hashmap_get(state->file_lock_map, session->filename);
    SentenceLock* sen_lock = get_held_sentence_lock(lock_info, session->sentence_index);
    
    if (!lock_info || !sen_lock) { 
        safe_printf("SS %u: CRITICAL: ETIRW with no locks held!\n", state->ss_id);
        if (sen_lock) pthread_mutex_unlock(&sen_lock->mutex);
        free_write_session(session);
        return -1;
    }

    // 3. Acquire the *full* file write lock
    safe_printf("SS %u: ETIRW acquiring WRLOCK for '%s'\n", state->ss_id, session->filename);
    if (pthread_rwlock_wrlock(&lock_info->content_rw_lock) != 0) {
        safe_printf("SS %u: ETIRW failed to get WRLOCK.\n", state->ss_id);
        pthread_mutex_unlock(&sen_lock->mutex);
        free_write_session(session);
        return -1;
    }
    safe_printf("SS %u: ETIRW WRLOCK acquired.\n", state->ss_id);

    // 4. Create the UNDO backup
    if (rename(final_path, backup_path) != 0) {
        if (errno == ENOENT) {
            safe_printf("SS %u: No original file to backup (new file).\n", state->ss_id);
            FILE* f = fopen(backup_path, "w");
            if(f) fclose(f);
        } else {
            perror("ss: etirw rename");
            pthread_rwlock_unlock(&lock_info->content_rw_lock);
            pthread_mutex_unlock(&sen_lock->mutex);
            free_write_session(session);
            return -1;
        }
    } else {
        safe_printf("SS %u: Created backup file '%s.bak'\n", state->ss_id, session->filename);
    }
    
    // 5. Apply changes from backup to new file
    if (apply_changes_to_file(state, session, backup_path, final_path) != 0) {
        safe_printf("SS %u: Failed to apply changes.\n", state->ss_id);
        pthread_rwlock_unlock(&lock_info->content_rw_lock);
        pthread_mutex_unlock(&sen_lock->mutex);
        free_write_session(session);
        return -1;
    }
    
    // 6. Release all locks
    pthread_rwlock_unlock(&lock_info->content_rw_lock);
    // Clear the sentence lock state 
    sen_lock->client_id = 0;
    sen_lock->lock_count = 0;
    pthread_mutex_unlock(&sen_lock->mutex);
    
    safe_printf("SS %u: ETIRW commit complete. All locks released.\n", state->ss_id);

    // 7. notify the nm to update its metadata

    struct stat st;
    uint64_t new_file_size = 0;
    if (stat(final_path, &st) == 0) {
        new_file_size = (uint64_t)st.st_size;
    }

    // Build the write complete packet
    MsgHeader nm_header = {0};
    MsgPayload nm_payload = {0};

    nm_header.version = PROTOCOL_VERSION;
    nm_header.opcode = OP_SS_NM_WRITE_COMPLETE; // Our new opcode
    nm_header.client_id = state->ss_id; // Identify ourselves as the SS
    nm_header.length = sizeof(MsgHeader) + sizeof(Payload_SSNMWriteComplete);
    
    strncpy(nm_payload.write_complete.filename, session->filename, MAX_FILENAME_LEN - 1);
    nm_payload.write_complete.new_file_size = new_file_size;

    // Send to NM (state->nm_socket_fd is the persistent connection)
    if (send_message(state->nm_socket_fd, &nm_header, &nm_payload) == -1){
        safe_printf("SS %u: CRITICAL: Failed to send WRITE_COMPLETE to NM.\n", state->ss_id);
    } else {
        safe_printf("SS %u: Notified NM of update to '%s'.\n", state->ss_id, session->filename);
    }

    // 8. Clean up the session
    free_write_session(session);
    return 0; // Success
}

/**
 * @brief Cleans up an abandoned write session (e.g., on client disconnect).
 * This finds the sentence lock held by the session and releases it.
 */
void handle_ss_write_cleanup(StorageServerState* state, WriteSession* session) {
    if (!session) return;
    
    safe_printf("SS %u: Cleaning up abandoned lock for '%s' (sent %u)\n",
        state->ss_id, session->filename, session->sentence_index);

    // 1. Find the file's lock info
    FileLockInfo* lock_info = ts_hashmap_get(state->file_lock_map, session->filename);
    if (lock_info == NULL) {
        safe_printf("SS %u: CRITICAL: Cannot find FileLockInfo for '%s' during cleanup.\n",
            state->ss_id, session->filename);
        return;
    }

    // 2. Find the specific sentence lock
    char sentence_key[16];
    snprintf(sentence_key, 16, "%u", session->sentence_index);
    
    // We must lock the map_mutex to safely read from the sentence_locks map
    pthread_mutex_lock(&lock_info->map_mutex);
    
    SentenceLock* sen_lock = ts_hashmap_get(lock_info->sentence_locks, sentence_key);
    
    if (sen_lock == NULL) {
        safe_printf("SS %u: CRITICAL: Cannot find SentenceLock for sent %u during cleanup.\n",
            state->ss_id, session->sentence_index);
        pthread_mutex_unlock(&lock_info->map_mutex);
        return;
    }
    
    sen_lock->client_id = 0;
    pthread_mutex_unlock(&sen_lock->mutex);
    
    // 4. Release the map mutex
    pthread_mutex_unlock(&lock_info->map_mutex);
    
    safe_printf("SS %u: Successfully released abandoned lock for sent %u.\n",
        state->ss_id, session->sentence_index);
}