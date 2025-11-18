#include "nm_state.h"
#include "utils.h"
#include "common.h"
#include <stdbool.h>
#include <sys/stat.h>
#include "nm_persistence.h"

typedef struct {
    TSHashMap* file_metadata_map;
    // helper to get rid of the file 
    // metadata when a SS leaves.
} FileCleanupArgs;

// Helper to convert an int socket to a string key
static void get_socket_key(int sock, char* key_buffer) {
    snprintf(key_buffer, 16, "%d", sock);
}

static void get_id_key(uint32_t id, char* key_buffer) {
    snprintf(key_buffer, 16, "%u", id);
}

uint32_t register_client(int sock, Payload_ClientRegisterReq* payload, NameServerState* state, ErrorCode* err_code) {
    safe_printf("── AUTH DEBUG ──\n");
    safe_printf("  Attempting to find user with password: \"%s\"\n", payload->username);
    // ── 1. Check if user *already exists* (LOGIN attempt) ──
    ClientInfo* client = ts_hashmap_get(state->client_username_map, payload->username);

    if (client != NULL) {
        
        if (client->is_active) {
            safe_printf("NM: Client '%s' (ID %u) already active. Rejecting.\n", payload->username, client->id);
            *err_code = ERR_ALREADY_ACTIVE;
            return 0;
        }

        // Check password
        if (strcmp(client->password, payload->password) != 0) {
            safe_printf("NM: Client '%s' provided invalid password.\n", payload->username);
            *err_code = ERR_ACCESS_DENIED; // "Invalid credentials"
            return 0;
        }

        // ── Success! This is a RE-LOGIN. ──
        uint32_t existing_id = client->id;
        client->socket_fd = sock;
        client->is_active = true;

        char socket_key[16];
        get_socket_key(sock, socket_key);
        SocketIdMapEntry* id_entry = malloc(sizeof(SocketIdMapEntry));
        id_entry->id = existing_id;
        ts_hashmap_put(state->socket_to_client_id_map, socket_key, id_entry);
        
        safe_printf("NM: Returning client '%s' logged in. (ID %u)\n", client->username, existing_id);
        *err_code = ERR_NONE;
        return existing_id;

    } 
    else {
        safe_printf("  DEBUG: User not found. Proceeding with new user registration.\n");
        safe_printf("── END DEBUG ──\n");
        // ── NEW USER REGISTRATION LOGIC ──
        safe_printf("NM: Username '%s' not found. Registering as new user.\n", payload->username);

        pthread_mutex_lock(&state->id_mutex);
        uint32_t new_id = state->next_client_id++;
        pthread_mutex_unlock(&state->id_mutex);

        ClientInfo* new_client = malloc(sizeof(ClientInfo));
        if (!new_client) {
            safe_printf("NM: CRITICAL: malloc failed for new client\n");
            *err_code = ERR_UNKNOWN;
            return 0;
        }
        
        new_client->id = new_id;
        new_client->socket_fd = sock;
        new_client->is_active = true;
        strncpy(new_client->username, payload->username, MAX_USERNAME_LEN - 1);
        strncpy(new_client->password, payload->password, MAX_PASSWORD_LEN - 1);
        
        char socket_key[16];
        char client_id_key[16];
        get_socket_key(sock, socket_key);
        get_id_key(new_id, client_id_key);

        SocketIdMapEntry* id_entry = malloc(sizeof(SocketIdMapEntry));
        id_entry->id = new_id;

        ts_hashmap_put(state->client_username_map, new_client->username, new_client);
        ts_hashmap_put(state->client_id_map, client_id_key, new_client);
        ts_hashmap_put(state->socket_to_client_id_map, socket_key, id_entry);
        
        // ── ATOMIC WRITE TO DISK ──
        persistence_log_op("USER,%s,%s", new_client->username, new_client->password);
        
        safe_printf("NM: Registered *new* client '%s' as Client %u\n", new_client->username, new_id);
        *err_code = ERR_NONE;
        return new_id;
    }
}

uint32_t register_ss(int sock, Payload_SSRegisterReq* payload, NameServerState* state) {
    // 1. Get a new unique ID
    pthread_mutex_lock(&state->id_mutex);
    uint32_t new_id = state->next_ss_id++;
    pthread_mutex_unlock(&state->id_mutex);
    
    char ss_key[16];
    snprintf(ss_key, 16, "%u", new_id);

    // 2. Malloc and populate the new struct
    StorageServerInfo* new_ss = malloc(sizeof(StorageServerInfo));
    if (!new_ss) {
        safe_printf("NM: CRITICAL: malloc failed for new SS\n");
        return 0;
    }
    
    new_ss->id = new_id; 
    new_ss->socket_fd = sock;
    strncpy(new_ss->ip, payload->ip, MAX_IP_LEN - 1);
    new_ss->ip[MAX_IP_LEN - 1] = '\0';
    new_ss->nm_port = payload->nm_port; 
    new_ss->client_port = payload->client_port;
    new_ss->file_list = ts_hashmap_create(); 
    
    // 3. Add to maps
    // We store (id_string -> StorageServerInfo*)
    ts_hashmap_put(state->ss_map, ss_key, new_ss);

    // We store (socket_fd -> id)
    SocketIdMapEntry* id_entry = malloc(sizeof(SocketIdMapEntry));
    id_entry->id = new_id;
    char socket_key[16];
    get_socket_key(sock, socket_key);
    ts_hashmap_put(state->socket_to_ss_id_map, socket_key, id_entry); 
    
    safe_printf("NM: Registered SS from %s:%u as SS %u\n", new_ss->ip, new_ss->client_port, new_id);
    return new_id;
}


typedef struct {
    NameServerState* state;
    uint32_t failed_ss_id;
} OrphanArgs;

// This callback will be run for every file in the dead SS's file_list
static void orphan_file_in_metadata_map_callback(const char* key, void* value, void* arg) {
    OrphanArgs* args = (OrphanArgs*)arg;
    NameServerState* state = args->state;
    uint32_t failed_ss_id = args->failed_ss_id;
    const char* filename = key;

    FileMetadata* meta = ts_hashmap_get(state->file_metadata_map, filename);
    if (meta) {
        pthread_mutex_lock(&meta->meta_lock);
        
        if (meta->ss_replicas[0] == failed_ss_id) {
            safe_printf("NM: File '%s' (Primary) is now orphaned (was on SS %u)\n", 
                filename, failed_ss_id);
            
            // --- FAILOVER: Promote Secondary to Primary ---
            if (meta->ss_replicas[1] != 0) {
                safe_printf("NM: Promoting SS %u to Primary for file '%s'.\n",
                    meta->ss_replicas[1], filename);
                meta->ss_replicas[0] = meta->ss_replicas[1];
                meta->ss_replicas[1] = 0;
            } else {
                meta->ss_replicas[0] = 0; // No secondary, file is fully orphaned
            }
            
        } else if (meta->ss_replicas[1] == failed_ss_id) {
            safe_printf("NM: File '%s' (Secondary) is now orphaned (was on SS %u)\n", 
                filename, failed_ss_id);
            meta->ss_replicas[1] = 0; // Just orphan the secondary
        }
        
        pthread_mutex_unlock(&meta->meta_lock);
    }
}

void handle_disconnect(int sock, NameServerState* state) {
    char socket_key[16];
    get_socket_key(sock, socket_key);

    // 1. Check if it was a Client
    SocketIdMapEntry* client_id_entry = ts_hashmap_remove(state->socket_to_client_id_map, socket_key);
    if (client_id_entry) {
        uint32_t client_id = client_id_entry->id;
        free(client_id_entry);

        char client_id_key[16];
        get_id_key(client_id, client_id_key);

        // Remove from the ID-keyed map (which owns the pointer)
        ClientInfo* client = ts_hashmap_get(state->client_id_map, client_id_key);
        
        if (client) {

            client->is_active = false;
            client->socket_fd = -1;
            safe_printf("NM: Client %u ('%s') on socket %d disconnected. Cleaning up.\n", client_id, client->username, sock);
        } else {
            safe_printf("NM: CRITICAL: Client %u was in socket_map but not client_id_map!\n", client_id);
        }
        
        close(sock); // Close the socket
        return; // It was a client, we're done.
    }

    // 2. Check if it was a Storage Server
    SocketIdMapEntry* ss_id_entry = ts_hashmap_remove(state->socket_to_ss_id_map, socket_key);
    if (ss_id_entry) {
        uint32_t ss_id = ss_id_entry->id;
        free(ss_id_entry);

        char ss_key[16];
        snprintf(ss_key, 16, "%u", ss_id);
        

        StorageServerInfo* ss = ts_hashmap_remove(state->ss_map, ss_key);
        if (ss) {
            safe_printf("NM: Removed SS %u from state.\n", ss_id);
            OrphanArgs args;
            args.state = state;
            args.failed_ss_id = ss_id;
            ts_hashmap_iterate(ss->file_list, orphan_file_in_metadata_map_callback, &args);
            safe_printf("NM: Removed SS %u's files from state.\n", ss_id);
            ts_hashmap_destroy(ss->file_list, NULL); // file_list values are TBD
            free(ss);
        } 
        else{
            safe_printf("NM: CRITICAL: SS %u was in socket_map but not ss_map\n", ss_id);
        }
        close(sock);
        return; // It was an SS, we're done.
    }

    // 3. If it was neither, it was a connection that failed before reg
    safe_printf("NM: Disconnect from unregistered socket %d\n", sock);
    close(sock);
    return;
}