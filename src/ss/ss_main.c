#include "protocol.h"
#include "utils.h"
#include "ss_structs.h"
#include "common.h"
#include "ss_file_ops.h"
#include "ss_write_helpers.h" // <-- NEW INCLUDE
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include "ss_handler.h"

// Prototypes for local functions
void handle_nm_request(StorageServerState* state, int nm_sock, MsgHeader* header, MsgPayload* payload);
void* handle_client_connection(void* arg);

// -----------------------------------------------------------------

// We need a helper struct to pass args to the handler thread
typedef struct {
    int socket_fd;
    StorageServerState* state;
} ThreadArgs;

// Global state for the Storage Server
StorageServerState server_state;

typedef struct {
    int nm_socket;
    uint32_t ss_id;
    StorageServerState* state;
    //BRUH
} SyncFileArgs;

// Callback function to send one file's info
static void sync_file_to_nm_callback(const char* key, void* value, void* arg) {
    SyncFileArgs* args = (SyncFileArgs*)arg;
    const char* filename = key;
    StorageServerState* state = args->state;

    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, filename);

    struct stat st;
    uint64_t file_size = 0;
    if (stat(file_path, &st) == 0) {
        file_size = (uint64_t)st.st_size;
    } 
    else {
        safe_printf("SS %u: Could not stat file '%s' for filesize in SS\n", args->ss_id, filename);
    }

    MsgHeader header = {0};
    MsgPayload payload = {0};

    header.version = PROTOCOL_VERSION;
    header.opcode = OP_SS_SYNC_FILE_INFO;
    header.client_id = args->ss_id; // Identify ourselves
    header.length = sizeof(MsgHeader) + sizeof(Payload_SSSyncFile);
    strncpy(payload.ss_sync.filename, filename, MAX_FILENAME_LEN - 1);
    payload.ss_sync.file_size = file_size;

    safe_printf("SS %u: Syncing file '%s' with NM.\n", args->ss_id, filename);
    if (send_message(args->nm_socket, &header, &payload) == -1) {
        safe_printf("SS %u: Failed to sync file '%s' to NM.\n", args->ss_id, filename);
    }
}


// Thread to handle this SS's *server* part (listening for clients)
void* run_client_server(void* arg) {
    StorageServerState* state = (StorageServerState*)arg;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    safe_printf("SS Client Server starting on port %d\n", state->client_port);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("SS server socket"); exit(EXIT_FAILURE);
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("SS server setsockopt"); exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(state->client_port);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("SS server bind"); exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 100) < 0) {
        perror("SS server listen"); exit(EXIT_FAILURE);
    }

    // Accept loop for clients
    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("SS server accept");
            continue;
        }

        // We need to pass socket + state to the handler thread
        ThreadArgs* args = malloc(sizeof(ThreadArgs));
        args->socket_fd = new_socket;
        args->state = state;

        pthread_t thread_id;
        // This call is now valid because the prototype exists
        if (pthread_create(&thread_id, NULL, handle_client_connection, (void*)args) != 0) {
            perror("SS server pthread_create");
            close(new_socket);
            free(args);
        }
        pthread_detach(thread_id);
    }
    return NULL;
}

// Thread to manage connection to the Name Server
void* run_nm_client(void* arg) {
    StorageServerState* state = (StorageServerState*)arg;
    struct sockaddr_in nm_addr;
    
    // Connect to NM
    if ((state->nm_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("NM client socket"); exit(EXIT_FAILURE);
    }
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_port = htons(state->nm_port);
    if(inet_pton(AF_INET, state->nm_ip, &nm_addr.sin_addr) <= 0) {
        perror("NM client inet_pton"); exit(EXIT_FAILURE);
    }
    if (connect(state->nm_socket_fd, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0) {
        perror("NM client connect"); exit(EXIT_FAILURE);
    }
    
    safe_printf("SS connected to Name Server at %s:%d\n", state->nm_ip, state->nm_port);

    // --- Send Registration Packet ---
    MsgHeader header;
    MsgPayload payload;
    memset(&header, 0, sizeof(header));
    memset(&payload, 0, sizeof(payload));

    header.version = PROTOCOL_VERSION;
    header.opcode = OP_SS_REGISTER_REQ;
    header.length = sizeof(MsgHeader) + sizeof(Payload_SSRegisterReq);

    Payload_SSRegisterReq* req = &payload.ss_reg_req;
    req->ss_id = 0; // Fresh connection
    req->is_reconnect = 0;
    
    // --- THIS IS THE FIX FROM LAST TIME ---
    // We get the public_ip from the state, which main() will set
    strncpy(req->ip, state->public_ip, MAX_IP_LEN - 1); 
    req->nm_port = 0; // Not needed
    req->client_port = state->client_port;
    
    if (send_message(state->nm_socket_fd, &header, &payload) == -1) {
        safe_printf("Failed to send registration to NM\n");
        close(state->nm_socket_fd);
        exit(EXIT_FAILURE);
    }
    
    // --- WAIT FOR THE RESPONSE ---
    if (recv_message(state->nm_socket_fd, &header, &payload) <= 0) {
        safe_printf("NM disconnected during registration response.\n");
        close(state->nm_socket_fd);
        exit(EXIT_FAILURE);
    }

    if (header.opcode != OP_SS_REGISTER_RES || header.error != ERR_NONE) {
        safe_printf("NM rejected SS registration. Error: %u\n", header.error);
        close(state->nm_socket_fd);
        exit(EXIT_FAILURE);
    }
    
    // --- STORE THE ID ---
    state->ss_id = header.client_id; // The NM puts our new ID in the client_id field
    safe_printf("SS successfully registered with NM. The ID is %u\n", state->ss_id);

    // Now that we are registered, tell the NM about all our files.
    safe_printf("SS %u: Beginning file list sync with NM...\n", state->ss_id);
    SyncFileArgs sync_args;
    sync_args.nm_socket = state->nm_socket_fd;
    sync_args.ss_id = state->ss_id;
    sync_args.state = state;
    
    // Iterate our map and call the sync callback for each file
    ts_hashmap_iterate(state->file_lock_map, sync_file_to_nm_callback, &sync_args);
    
    safe_printf("SS %u: File list sync complete.\n", state->ss_id);
    
    // --- REAL LISTEN LOOP ---
    while(recv_message(state->nm_socket_fd, &header, &payload) > 0) {
        // We got a command *from* the NM. Handle it.
        handle_nm_request(state, state->nm_socket_fd, &header, &payload);
    }

    safe_printf("SS: Lost connection to Name Server. Exiting.\n");
    close(state->nm_socket_fd);
    exit(EXIT_FAILURE); // If the NM dies, we die.
    
    return NULL;
}

int main(int argc, char const *argv[]) {
    // --- UPDATED ARGC CHECK ---
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <data_dir> <public_ip> <nm_ip> <nm_port> <client_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* data_dir = argv[1];
    const char* public_ip = argv[2]; // <-- NEW
    const char* nm_ip = argv[3];
    uint16_t nm_port = (uint16_t)atoi(argv[4]);
    uint16_t client_port = (uint16_t)atoi(argv[5]);

    init_printf_mutex();
    
    // --- PASS NEW ARG TO INIT ---
    // This call is now valid because the prototype matches
    init_ss_state(&server_state, data_dir, nm_ip, nm_port, client_port, public_ip);
    
    safe_printf("─── Docs++ Storage Server v%u Starting ───\n", PROTOCOL_VERSION);

    pthread_t nm_thread_id, server_thread_id;

    // Start thread to connect to NM
    if (pthread_create(&nm_thread_id, NULL, run_nm_client, (void*)&server_state) != 0) {
        perror("pthread_create (nm_client)"); exit(EXIT_FAILURE);
    }

    // Start thread to listen for clients
    if (pthread_create(&server_thread_id, NULL, run_client_server, (void*)&server_state) != 0) {
        perror("pthread_create (client_server)"); exit(EXIT_FAILURE);
    }

    // Wait for threads to finish (they won't)
    pthread_join(nm_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    destroy_printf_mutex();
    return 0;
}