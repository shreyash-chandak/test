#include "nm_state.h"
#include "utils.h"
#include "common.h"
#include <stdbool.h>
#include <sys/stat.h>

#define USER_FILE_PATH "persistentstore/users.txt"
static pthread_mutex_t user_file_mutex;

void init_user_file_mutex(void) {
    pthread_mutex_init(&user_file_mutex, NULL);
}

void destroy_user_file_mutex(void) {
    pthread_mutex_destroy(&user_file_mutex);
}


// Helper to convert an int socket to a string key
static void get_socket_key(int sock, char* key_buffer) {
    snprintf(key_buffer, 16, "%d", sock);
}

static void get_id_key(uint32_t id, char* key_buffer) {
    snprintf(key_buffer, 16, "%u", id);
}

static void append_user_to_store(const char* username, const char* password) {
    pthread_mutex_lock(&user_file_mutex);
    
    FILE* file = fopen(USER_FILE_PATH, "a");
    if (file == NULL) {
        // Attempt to create the directory if it doesn't exist
        mkdir("persistentstore", 0755); // 0755 = rwxr-xr-x
        file = fopen(USER_FILE_PATH, "a");
        if (file == NULL) {
            safe_printf("NM: CRITICAL: Failed to create or open %s.\n", USER_FILE_PATH);
            pthread_mutex_unlock(&user_file_mutex);
            return;
        }
    }
    
    fprintf(file, "%s,%s\n", username, password);
    fclose(file);
    
    pthread_mutex_unlock(&user_file_mutex);
}

void load_persistent_users(NameServerState* state) {
    pthread_mutex_lock(&user_file_mutex); // Lock before reading
    
    FILE* file = fopen(USER_FILE_PATH, "r");
    if (file == NULL) {
        safe_printf("NM: No persistent user file found. Starting fresh.\n");
        pthread_mutex_unlock(&user_file_mutex);
        return;
    }
    
    char line_buffer[MAX_USERNAME_LEN + MAX_PASSWORD_LEN + 2];
    int count = 0;
    
    while (fgets(line_buffer, sizeof(line_buffer), file)) {
        line_buffer[strcspn(line_buffer, "\r\n")] = 0;
        if (strlen(line_buffer) == 0) continue; // Skip empty lines

        char* username = strtok(line_buffer, ",");
        char* password = strtok(NULL, ",");

        if (username && password) {
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
            get_id_key(new_id, client_id_key);
            ts_hashmap_put(state->client_username_map, client->username, client);
            ts_hashmap_put(state->client_id_map, client_id_key, client);
            
            count++;
        }
    }
    
    fclose(file);
    pthread_mutex_unlock(&user_file_mutex);
    safe_printf("NM: Preloaded %d persistent users.\n", count);
}

uint32_t register_client(int sock, Payload_ClientRegisterReq* payload, NameServerState* state, ErrorCode* err_code) {
    safe_printf("--- AUTH DEBUG ---\n");
    safe_printf("  Attempting to find user with key: \"%s\"\n", payload->username);
    // --- 1. Check if user *already exists* (LOGIN attempt) ---
    ClientInfo* client = ts_hashmap_get(state->client_username_map, payload->username);

    if (client != NULL) {
        safe_printf("  DEBUG: Found existing user. Checking password...\n");
        safe_printf("--- END DEBUG ---\n");
        // --- LOGIN LOGIC ---
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

        // --- Success! This is a RE-LOGIN. ---
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

    } else {
        safe_printf("  DEBUG: User not found. Proceeding with new user registration.\n");
        safe_printf("--- END DEBUG ---\n");
        // --- NEW USER REGISTRATION LOGIC ---
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
        
        // --- ATOMIC WRITE TO DISK ---
        append_user_to_store(new_client->username, new_client->password);

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
    
    new_ss->id = new_id; // <-- FIX: This member now exists
    new_ss->socket_fd = sock;
    strncpy(new_ss->ip, payload->ip, MAX_IP_LEN - 1);
    new_ss->ip[MAX_IP_LEN - 1] = '\0';
    new_ss->nm_port = payload->nm_port; // <-- FIX: This member now exists
    new_ss->client_port = payload->client_port;
    new_ss->file_list = ts_hashmap_create(); // <-- FIX: This member now exists
    
    // 3. Add to maps
    // We store (id_string -> StorageServerInfo*)
    ts_hashmap_put(state->ss_map, ss_key, new_ss);

    // We store (socket_fd -> id)
    SocketIdMapEntry* id_entry = malloc(sizeof(SocketIdMapEntry));
    id_entry->id = new_id;
    char socket_key[16];
    get_socket_key(sock, socket_key);
    ts_hashmap_put(state->socket_to_ss_id_map, socket_key, id_entry); // <-- FIX: Use new map
    
    safe_printf("NM: Registered SS from %s:%u as SS %u\n", new_ss->ip, new_ss->client_port, new_id);
    return new_id;
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
        
        // Now we can remove from the main ss_map
        StorageServerInfo* ss = ts_hashmap_remove(state->ss_map, ss_key);
        if (ss) {
            safe_printf("NM: Removed SS %u from state.\n", ss_id);
            // --- FIX: Use correct destroy function ---
            ts_hashmap_destroy(ss->file_list, NULL); // file_list values are TBD
            free(ss);
        } else {
            safe_printf("NM: CRITICAL: SS %u was in socket_map but not ss_map!\n", ss_id);
        }
        close(sock);
        return; // It was an SS, we're done.
    }

    // 3. If it was neither, it was a connection that failed before reg
    safe_printf("NM: Disconnect from unregistered socket %d\n", sock);
    close(sock);
    return;
}

