#include "nm_persistence.h"
#include "utils.h"
#include "common.h"
#include <sys/stat.h>
#include <stdarg.h> // For va_list

#define USER_LOG_PATH "persistentstore/users.log"
#define META_LOG_PATH "persistentstore/metadata.log"

static pthread_mutex_t user_log_mutex;
static pthread_mutex_t meta_log_mutex;

// --- Internal Helper: Creates the directory ---
static void ensure_persistent_dir(void) {
    mkdir("persistentstore", 0755);
}

// --- Public API Implementation ---

void persistence_init(void) {
    pthread_mutex_init(&user_log_mutex, NULL);
    pthread_mutex_init(&meta_log_mutex, NULL);
    ensure_persistent_dir();
}

void persistence_destroy(void) {
    pthread_mutex_destroy(&user_log_mutex);
    pthread_mutex_destroy(&meta_log_mutex);
}

void persistence_log_op(const char* format, ...) {
    // 1. Determine which log to write to
    const char* file_path;
    pthread_mutex_t* mutex;

    if (strncmp(format, "USER,", 5) == 0) {
        file_path = USER_LOG_PATH;
        mutex = &user_log_mutex;
    } else if (strncmp(format, "META,", 5) == 0) {
        file_path = META_LOG_PATH;
        mutex = &meta_log_mutex;
    } else {
        safe_printf("NM: CRITICAL: Unknown log format '%s'\n", format);
        return;
    }

    // 2. Lock and write to the chosen file
    pthread_mutex_lock(mutex);

    FILE* file = fopen(file_path, "a");
    if (file == NULL) {
        safe_printf("NM: CRITICAL: Failed to open log '%s'.\n", file_path);
        pthread_mutex_unlock(mutex);
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    fprintf(file, "\n"); // Always add a newline
    va_end(args);

    fclose(file);
    pthread_mutex_unlock(mutex);
}

// --- Internal Loader Functions ---

static void load_users(NameServerState* state) {
    FILE* file = fopen(USER_LOG_PATH, "r");
    if (file == NULL) {
        safe_printf("NM: No persistent user log found. Starting fresh.\n");
        return;
    }
    
    char line[MAX_USERNAME_LEN + MAX_PASSWORD_LEN + 10];
    int count = 0;
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        
        char* type = strtok(line, ",");
        if (type == NULL) continue;
        
        if (strcmp(type, "USER") == 0) {
            char* username = strtok(NULL, ",");
            char* password = strtok(NULL, ",");

            if (username && password) {
                // This logic is from your old nm_state.c
                pthread_mutex_lock(&state->id_mutex);
                uint32_t new_id = state->next_client_id++;
                pthread_mutex_unlock(&state->id_mutex);
                
                ClientInfo* client = malloc(sizeof(ClientInfo));
                client->id = new_id;
                client->socket_fd = -1;
                client->is_active = false;
                strncpy(client->username, username, MAX_USERNAME_LEN - 1);
                strncpy(client->password, password, MAX_PASSWORD_LEN - 1);
                
                char client_id_key[16];
                snprintf(client_id_key, 16, "%u", new_id);
                
                ts_hashmap_put(state->client_username_map, client->username, client);
                ts_hashmap_put(state->client_id_map, client_id_key, client);
                count++;
            }
        }
    }
    fclose(file);
    safe_printf("\nNM: Preloaded %d persistent users.\n", count);
}

static FileMetadata* get_or_create_meta(NameServerState* state, const char* filename) {
    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, filename);
    if (meta == NULL) {
        
        meta = (FileMetadata*)malloc(sizeof(FileMetadata));
        if (meta == NULL) {
            safe_printf("CRITICAL: malloc failed in get_or_create_meta\n");
            return NULL;
        }
        memset(meta, 0, sizeof(FileMetadata));

        strncpy(meta->filename, filename, MAX_FILENAME_LEN - 1);
        meta->filename[MAX_FILENAME_LEN - 1] = '\0';
        meta->access_list = ts_hashmap_create();
        meta->pending_requests = ts_hashmap_create();
        pthread_mutex_init(&meta->meta_lock, NULL);
        ts_hashmap_put(state->file_metadata_map, filename, meta);
    }
    return meta;
}


static void load_metadata(NameServerState* state) {
    
    
    FILE* file = fopen(META_LOG_PATH, "r");
    
    if(file == NULL){
        safe_printf("NM: No persistent metadata log found. Starting fresh.\n");
        return;
    }
    
    char line[MAX_BUFFER_LEN];
    int count = 0;

    while(fgets(line, sizeof(line), file)){
        
        line[strcspn(line, "\r\n")] = 0;
        
        char* type = strtok(line, ",");

        if(type == NULL)
            continue;

        if(strcmp(type, "META") == 0){

            char* operation = strtok(NULL, ",");
            if (operation == NULL) continue;
            count++;
            if (strcmp(operation, "CREATE") == 0) {
                // Format: META,CREATE,<file>,<owner>,<ss_id_1>,<ss_id_2>,<timestamp>
                char* filename = strtok(NULL, ",");
                char* owner = strtok(NULL, ",");
                char* ss_id1_str = strtok(NULL, ",");
                char* ss_id2_str = strtok(NULL, ","); 
                char* created_str = strtok(NULL, ",");

                if (filename && owner && ss_id1_str && ss_id2_str && created_str) { 
                    FileMetadata* new_meta = malloc(sizeof(FileMetadata));
                    if (!new_meta) { 
                        safe_printf("NM: CRITICAL: malloc failed while loading metadata for '%s'. Skipping.\n", filename);
                        continue; // Skip to the next log entry so we don't crash
                    }
                    
                    pthread_mutex_init(&new_meta->meta_lock, NULL); 
                    strncpy(new_meta->filename, filename, MAX_FILENAME_LEN - 1);
                    strncpy(new_meta->owner_username, owner, MAX_USERNAME_LEN - 1);
                    new_meta->ss_replicas[0] = (uint32_t)atoi(ss_id1_str);
                    new_meta->ss_replicas[1] = (uint32_t)atoi(ss_id2_str);
                    new_meta->created_at = (uint64_t)atoll(created_str);
                    new_meta->modified_at = new_meta->created_at;
                    new_meta->accessed_at = new_meta->created_at;
                    new_meta->file_size = 0; // Will be updated by SS sync
                    new_meta->access_list = ts_hashmap_create();
                    char* owner_permission = strdup("RW");
                    ts_hashmap_put(new_meta->access_list, owner, (void*)owner_permission);
                    new_meta->pending_requests = ts_hashmap_create();
                    ts_hashmap_put(state->file_metadata_map, new_meta->filename, new_meta);
                }
            }
            else if (strcmp(operation, "WRITE") == 0) {
                // Processes: META,WRITE,<filename>,<timestamp>,<file_size>
                char* filename = strtok(NULL, ",");
                char* timestamp_str = strtok(NULL, ",");
                char* size_str = strtok(NULL, ",");
                
                if (filename && timestamp_str && size_str) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    
                    uint64_t timestamp = (uint64_t)atol(timestamp_str);
                    uint64_t file_size = (uint64_t)atoll(size_str);

                    meta->modified_at = timestamp; 
                    meta->accessed_at = timestamp;
                    meta->file_size = file_size;
                }
            }
            else if (strcmp(operation, "UNDO") == 0) {
                // Processes: META,UNDO,<filename>,<timestamp>,<file_size>
                char* filename = strtok(NULL, ",");
                char* timestamp_str = strtok(NULL, ",");
                char* size_str = strtok(NULL, ",");
                
                if (filename && timestamp_str && size_str) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    
                    uint64_t timestamp = (uint64_t)atol(timestamp_str);
                    uint64_t file_size = (uint64_t)atoll(size_str);

                    // An UNDO log updates all three fields, just like a WRITE
                    meta->modified_at = timestamp;
                    meta->accessed_at = timestamp; 
                    meta->file_size = file_size;
                }
            }
            else if (strcmp(operation, "REDO") == 0) { 
                // Processes: META,REDO,<filename>,<timestamp>,<file_size>
                char* filename = strtok(NULL, ",");
                char* timestamp_str = strtok(NULL, ",");
                char* size_str = strtok(NULL, ",");
                
                if (filename && timestamp_str && size_str) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    
                    uint64_t timestamp = (uint64_t)atol(timestamp_str);
                    uint64_t file_size = (uint64_t)atoll(size_str);

                    // A REDO log updates all three fields, just like a WRITE
                    meta->modified_at = timestamp;
                    meta->accessed_at = timestamp; 
                    meta->file_size = file_size;
                }
            } else if (strcmp(operation, "REVERT") == 0) { 
                // Processes: META,REVERT,<filename>,<timestamp>,<file_size>
                char* filename = strtok(NULL, ",");
                char* timestamp_str = strtok(NULL, ",");
                char* size_str = strtok(NULL, ",");

                if (filename && timestamp_str && size_str) {
                    FileMetadata* meta = get_or_create_meta(state, filename);

                    uint64_t timestamp = (uint64_t)atol(timestamp_str);
                    uint64_t file_size = (uint64_t)atoll(size_str);

                    // A REVERT log updates all three fields, just like a WRITE
                    meta->modified_at = timestamp;
                    meta->accessed_at = timestamp; 
                    meta->file_size = file_size;
                }
            }
            else if (strcmp(operation, "SET_LAST_ACCESSED") == 0) {
                char* filename = strtok(NULL, ",");
                char* timestamp_str = strtok(NULL, ",");
                if (filename && timestamp_str) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    meta->accessed_at = atol(timestamp_str);
                }
            }
            else if (strcmp(operation, "SET_LAST_MODIFIED") == 0) {
                char* filename = strtok(NULL, ",");
                char* timestamp_str = strtok(NULL, ",");
                if (filename && timestamp_str) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    meta->modified_at = atol(timestamp_str);
                }
            }
            else if (strcmp(operation, "ADDACCESS") == 0) {
                char* filename = strtok(NULL, ",");
                char* user = strtok(NULL, ",");
                char* level = strtok(NULL, ",");
                if (filename && user && level) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    char* level_alloc = strdup(level);
                    void* old_level = ts_hashmap_remove(meta->access_list, user);
                    if (old_level) {
                        free(old_level);
                    }
                    ts_hashmap_put(meta->access_list, user, level_alloc);
                }
            }
            else if (strcmp(operation, "REMACCESS") == 0) {
                char* filename = strtok(NULL, ",");
                char* user = strtok(NULL, ",");
                if (filename && user) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    ts_hashmap_remove(meta->access_list, user);
                }
            }
            else if (strcmp(operation, "REQACCESS") == 0) {
                char* filename = strtok(NULL, ",");
                char* username = strtok(NULL, ",");
                if (filename && username) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    ts_hashmap_put(meta->pending_requests, username, (void*)1);
                }
            }
            else if (strcmp(operation, "REMREQ") == 0) {
                char* filename = strtok(NULL, ",");
                char* username = strtok(NULL, ",");
                if (filename && username) {
                    FileMetadata* meta = get_or_create_meta(state, filename);
                    ts_hashmap_remove(meta->pending_requests, username);
                }
            }
            else if (strcmp(operation, "DELETE") == 0) {
                // Processes: META,DELETE,<filename>
                char* filename = strtok(NULL, ",");
                
                if (filename) {
                    // Find and remove the metadata from the map
                    void* old_meta = ts_hashmap_remove(state->file_metadata_map, filename);
                    
                    if (old_meta) {
                        // Use our new helper to free it completely
                        free_file_metadata(old_meta);
                    }
                }
            }
        }
    }
    fclose(file);
    safe_printf("NM: Replayed %d Journaling metadata operations.\n\n", count);
}

void persistence_load_state(NameServerState* state) {
    load_users(state);
    load_metadata(state);
}