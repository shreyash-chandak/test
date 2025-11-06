#include "protocol.h"
#include "utils.h"
#include "nm_structs.h"
#include "nm_handler.h"
#include "common.h"
#include "nm_state.h"

#define NM_PORT 8080
#define MAX_CONNECTIONS 100

// This will be implemented in nm_state.c
void init_server_state(NameServerState* state);
void destroy_server_state(NameServerState* state); // For clean shutdown
void load_persistent_users(NameServerState* state); // <-- ADD
void init_user_file_mutex(void);  // <-- ADD
void destroy_user_file_mutex(void); // <-- ADD

// Global state for the Name Server
NameServerState server_state;

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    init_printf_mutex();
    init_server_state(&server_state);
    init_user_file_mutex();

    // get username/pwd/active/socket
    // statuses of all registered users so far
    load_persistent_users(&server_state);

    safe_printf("--- Docs++ Name Server v%u Starting ---\n", PROTOCOL_VERSION);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attach socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(NM_PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    safe_printf("Name Server listening on port %d\n", NM_PORT);

    // Accept loop
    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("accept");
            continue; // Keep listening
        }

        ThreadArgs* args = malloc(sizeof(ThreadArgs));
        if (!args) {
            perror("malloc failed for ThreadArgs");
            close(new_socket);
            continue;
        }
        args->socket_fd = new_socket;
        args->state = &server_state;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_connection, (void*)args) != 0) {
            perror("pthread_create failed");
            close(new_socket);
            free(args);
        }
        
        pthread_detach(thread_id);
    }

    // Cleanup
    close(server_fd);
    destroy_server_state(&server_state); // Free all maps
    destroy_printf_mutex();
    return 0;
}


void init_server_state(NameServerState* state) {
    state->file_metadata_map = ts_hashmap_create();
    state->client_username_map = ts_hashmap_create();
    state->client_id_map = ts_hashmap_create();
    state->ss_map = ts_hashmap_create();
    
    state->socket_to_client_id_map = ts_hashmap_create();
    state->socket_to_ss_id_map = ts_hashmap_create();

    state->next_client_id = 1;
    state->next_ss_id = 1;
    pthread_mutex_init(&state->id_mutex, NULL);

    // TODO: Load persistent metadata from disk
    safe_printf("Server state initialized.\n");
}

// Helper to free the value pointers in the maps
void free_client_info(void* val){
    free(val);
}

void free_ss_info(void* val) { 
    StorageServerInfo* ss_info = (StorageServerInfo*)val;
    ts_hashmap_destroy(ss_info->file_list, NULL); // Assuming file_list values are simple
    free(ss_info);
}

void free_socket_id_entry(void* val){
    free(val);
}

void destroy_server_state(NameServerState* state) {
    
    // The client_id_map OWNS the ClientInfo pointers.
    // The client_username_map just BORROWS them.
    // We pass NULL to the username_map's destroy to prevent a double-free.
    
    ts_hashmap_destroy(state->client_username_map, NULL); // <-- FIX
    ts_hashmap_destroy(state->client_id_map, free_client_info); // <-- OWNER

    ts_hashmap_destroy(state->ss_map, free_ss_info);
    ts_hashmap_destroy(state->socket_to_client_id_map, free_socket_id_entry);
    ts_hashmap_destroy(state->socket_to_ss_id_map, free_socket_id_entry);
    pthread_mutex_destroy(&state->id_mutex);
    safe_printf("Server state destroyed.\n");

}