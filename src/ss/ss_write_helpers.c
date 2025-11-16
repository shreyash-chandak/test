#include "ss_write_helpers.h"
#include "ss_file_ops.h" // For send_ss_error
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <errno.h>    // For errno, ENOENT
#include <ctype.h>    // For isspace
#include <sys/stat.h> // For stat
#include <dirent.h>   // For opendir

// --- Helper Functions (Moved from ss_main.c) ---

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

/**
 * @brief Reads a single sentence (ending in . ! ?) from a file.
 */
static char* read_sentence(FILE* fp, int* delim) {
    size_t size = 128;
    char* buffer = malloc(size);
    if (!buffer) return NULL;

    int c;
    size_t i = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (i >= size - 1) {
            size *= 2;
            char* new_buffer = realloc(buffer, size);
            if (!new_buffer) { free(buffer); return NULL; }
            buffer = new_buffer;
        }
        buffer[i++] = (char)c;
        if (c == '.' || c == '!' || c == '?') {*delim = 1; break;}
    }
    buffer[i] = '\0';
    if (i == 0) { free(buffer); return NULL; }
    
    char* start = buffer;
    while(isspace(*start)) start++;
    if(strlen(start) == 0) { free(buffer); return NULL; }
    if (start != buffer) memmove(buffer, start, strlen(start) + 1);
    return buffer;
}

static uint32_t get_sentence_count(StorageServerState* state, const char* filename) {
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, filename);
    
    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        return 0; // File doesn't exist, so 0 sentences
    }
    
    int delim = 0;
    uint32_t count = 0;
    char* sentence = read_sentence(fp,&delim);
    while (sentence != NULL && delim) {
        count++;
        free(sentence);
        delim = 0;
        sentence = read_sentence(fp,&delim);
    }
    if (sentence != NULL) free(sentence);

    fclose(fp);
    return count;
}

/**
 * @brief Helper to qsort: Compare WriteOps by word_index
 */
static int compare_write_ops(const void* a, const void* b) {
    WriteOp* opA = *(WriteOp**)a;
    WriteOp* opB = *(WriteOp**)b;
    return (int)opA->word_index - (int)opB->word_index;
}

/**
 * @brief Helper to apply a *single* WriteOp to a sentence.
 * Returns a new, malloc'd string with the result.
 */
static char* apply_single_op(const char* original_sentence, WriteOp* op) {
    // --- 1. Tokenize the original sentence ---
    char* sentence_copy = strdup(original_sentence);
    char delimiter[2] = {0}; // To store the final '.', '!', or '?'
    
    char* delim_ptr = strpbrk(sentence_copy, ".!?");
    if (delim_ptr) {
        delimiter[0] = *delim_ptr; // Save the delimiter
        *delim_ptr = '\0';         // Cut the sentence
    }

    char* words[MAX_BUFFER_LEN]; 
    size_t word_count = 0;
    char* token = strtok(sentence_copy, " ");
    while(token && word_count < MAX_BUFFER_LEN) {
        if (strlen(token) > 0) {
            words[word_count++] = token;
        }
        token = strtok(NULL, " ");
    }

    // --- 2. Build the new word list by merging ---
    // We need +1 for the new word, and +1 for safety
    char* new_words[MAX_BUFFER_LEN + 2];
    size_t new_word_count = 0;
    size_t word_idx = 0;
    bool op_inserted = false;

    // Loop until we've placed all original words AND the new op
    while (word_idx < word_count || !op_inserted) {
        
        // If this is the correct index, insert the new content
        if (!op_inserted && word_idx == op->word_index) {
            new_words[new_word_count++] = op->content;
            op_inserted = true;
            // NOTE: We DO NOT increment word_idx. This is an insert.
        }
        
        // If there are original words left, add the next one
        else if (word_idx < word_count) {
            new_words[new_word_count++] = words[word_idx];
            word_idx++;
        } 
        // If we're at the end and still haven't inserted, append the op
        else if (!op_inserted) {
            new_words[new_word_count++] = op->content;
            op_inserted = true;
        }
    }
    
    // --- 3. Concatenate the new word list into a final string ---
    // (This allocation is an estimate, but should be safe)
    char* new_sentence = malloc(strlen(original_sentence) + MAX_WRITE_CONTENT_LEN + 128); 
    new_sentence[0] = '\0';
    
    for(size_t i = 0; i < new_word_count; i++) {
        strcat(new_sentence, new_words[i]);
        if (i < new_word_count-1) {
            strcat(new_sentence, " ");
        }
    }
    
    // --- 4. Add the delimiter back *if* it existed ---
    if (delimiter[0] != 0) {
        strcat(new_sentence, delimiter);
    }

    free(sentence_copy);
    return new_sentence;
}

/**
 * @brief Applies the list of WriteOps to a single sentence string.
 * --- THIS IS THE NEW, CORRECTED IMPLEMENTATION ---
 */
static char* apply_ops_to_sentence(const char* original_sentence, WriteOp* ops_list) {
    
    // --- 1. Put all ops into a temporary array ---
    size_t op_count = 0;
    WriteOp* op = ops_list;
    while(op) { op_count++; op = op->next; }

    if (op_count == 0) {
        return strdup(original_sentence); // No changes
    }
    
    WriteOp** op_array = malloc(sizeof(WriteOp*) * op_count);
    op = ops_list;
    for(size_t i = 0; i < op_count; i++) {
        op_array[i] = op;
        op = op->next;
    }
    
    // --- 2. Initialize the sentence state ---
    char* current_sentence = strdup(original_sentence);

    // --- 3. Apply ops IN REVERSE ARRAY ORDER (which is FIFO) ---
    // The ops_list is a LIFO stack (new ops are prepended).
    // The array is also in LIFO order.
    // We must iterate the array backwards to get the FIFO order 
    // specified by the project doc.
    
    for (int i = (int)op_count - 1; i >= 0; i--) {
        WriteOp* current_op = op_array[i];
        
        // Apply the op to the *current* state
        char* next_sentence = apply_single_op(current_sentence, current_op);
        
        // Free the intermediate state
        free(current_sentence);
        
        // The result becomes the new current state for the next loop
        current_sentence = next_sentence;
    }

    // --- 4. Cleanup and return ---
    free(op_array); // Free the temp array (not the ops themselves)
    
    // current_sentence now holds the final, correct result
    return current_sentence;
}

/**
 * @brief This is the *REAL* file-merge logic.
 */
int apply_changes_to_file(StorageServerState* state, WriteSession* session, const char* tmp_path, const char* final_path) {
    FILE* in = fopen(tmp_path, "r");
    FILE* out = fopen(final_path, "w");
    
    if (!out) {
        safe_printf("SS: apply_changes: Could not open final file for writing.\n");
        if (in) fclose(in);
        return -1;
    }
    
    // Handle new file creation (no backup)
    if (!in) {
        safe_printf("SS: apply_changes: No backup, creating new file.\n");
        if (session->sentence_index != 0) {
            safe_printf("SS: apply_changes: Error: Index %u out of bounds for new file.\n", session->sentence_index);
            fclose(out);
            return -1; // Error
        }
        // This is a new file, just apply ops to an empty string
        char* new_sentence = apply_ops_to_sentence("", session->operations);
        fputs(new_sentence, out);
        free(new_sentence);
        fclose(out);
        return 0; // Success
    }

    safe_printf("SS: apply_changes: Merging file...\n");
    char* sentence;
    uint32_t current_sentence_index = 0;
    int result = 0, delim_local = 0;
    bool op_applied = false; // <-- THE FIX: Track if we've done the edit

    while ((sentence = read_sentence(in, &delim_local)) != NULL) {
        if (current_sentence_index == session->sentence_index) {
            safe_printf("SS: apply_changes: Modifying sentence %u\n", current_sentence_index);
            char* new_sentence = apply_ops_to_sentence(sentence, session->operations);
            fputs(new_sentence, out);
            free(new_sentence);
            op_applied = true; // <-- THE FIX: Mark as applied
        } else {
            // This sentence is not being edited, write it as-is
            fputs(sentence, out);
        }
        free(sentence); // Free the buffer from read_sentence
        
        // Add a space between sentences if we're not at the end
        int next_char = fgetc(in);
        if (next_char != EOF) {
            ungetc(next_char, in); // Put it back
            fputc(' ', out);
        }
        current_sentence_index++;
    }
    
    // Handle append:
    // If we did NOT apply an op AND the index is the end of the file
    if (!op_applied && session->sentence_index == current_sentence_index) {
        safe_printf("SS: apply_changes: Appending new sentence %u\n", current_sentence_index);
        char* new_sentence = apply_ops_to_sentence("", session->operations);
        if (current_sentence_index > 0) fputs(" ", out);
        fputs(new_sentence, out);
        free(new_sentence);
        op_applied = true; // Mark as applied
    }
    // Handle error:
    // If we finished and never applied the op (and it wasn't an append), the index was invalid.
    else if (!op_applied) {
        safe_printf("SS: apply_changes: Error: Sentence index %u out of bounds (%u)\n",
            session->sentence_index, current_sentence_index);
        result = -1; // This will fail the ETIRW
    }

    fclose(in);
    fclose(out);
    return result;
}

// --- Public API Functions (Moved from ss_file_ops.c and ss_main.c) ---

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
    // --- FIX: Safer snprintf ---
    snprintf(final_path, sizeof(final_path), "%s/%s", state->data_dir, session->filename);
    snprintf(backup_path, sizeof(backup_path), "%s.bak", final_path);

    // 2. Find the lock structs
    FileLockInfo* lock_info = ts_hashmap_get(state->file_lock_map, session->filename);
    SentenceLock* sen_lock = get_held_sentence_lock(lock_info, session->sentence_index);
    
    if (!lock_info || !sen_lock) { /* ... (rest of function is identical) ... */
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
    
    // 3. --- This is the fix ---
    // The lock is currently HELD by the disconnected client's thread.
    // We simply unlock it, making it available again.
    // We also reset the client_id just in case.
    sen_lock->client_id = 0;
    pthread_mutex_unlock(&sen_lock->mutex);
    
    // 4. Release the map mutex
    pthread_mutex_unlock(&lock_info->map_mutex);
    
    safe_printf("SS %u: Successfully released abandoned lock for sent %u.\n",
        state->ss_id, session->sentence_index);
}