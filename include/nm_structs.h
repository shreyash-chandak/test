#ifndef NM_STRUCTS_H
#define NM_STRUCTS_H

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include "protocol.h"
#include "ts_hashmap.h"

// --- THESE STRUCTS ARE NOW CORRECT ---

// Info about a connected client
typedef struct {
    uint32_t id; // <-- FIX: Added this field
    int socket_fd;
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN]; 
    bool is_active;                  // <-- ADD THIS
} ClientInfo;

// Info about a connected storage server
typedef struct {
    uint32_t id; // <-- FIX: Added this field
    int socket_fd;
    char ip[MAX_IP_LEN];
    uint16_t nm_port; // <-- FIX: Added this field
    uint16_t client_port;
    TSHashMap* file_list; // <-- FIX: Added this field (map of filename -> FileMetadata*)
} StorageServerInfo;

// Info about a specific file (value in the file_metadata_map)
typedef struct {
    char filename[MAX_FILENAME_LEN];
    uint32_t ss_id; // Which SS has this file
    char owner_username[MAX_USERNAME_LEN];
    // TODO: Add ACL list
} FileMetadata;

// Helper struct for the client_map
// We need this so we can find the client by ID to get the username
// to remove them from the username-keyed map.
typedef struct {
    char username[MAX_USERNAME_LEN];
} ClientMapEntry;

// Helper struct for the socket->id maps
// We need a pointer to a stable value
typedef struct {
    uint32_t id;
} SocketIdMapEntry;


// The main state for the entire Name Server
typedef struct {
    // --- MAPS ---
    // (filename -> FileMetadata*)
    TSHashMap* file_metadata_map; 
    
    // (username -> ClientInfo*)
    TSHashMap* client_username_map;

    // NEW MAP: Used for fast lookup by ID during disconnect.
    TSHashMap* client_id_map;
    
    // (ss_id_string -> StorageServerInfo*)
    TSHashMap* ss_map; 
    
    // --- FIX: Splitting the socket map ---
    // (socket_string -> SocketIdMapEntry*)
    TSHashMap* socket_to_client_id_map;
    // (socket_string -> SocketIdMapEntry*)
    TSHashMap* socket_to_ss_id_map;


    // --- ID Generation ---
    uint32_t next_client_id;
    uint32_t next_ss_id;
    pthread_mutex_t id_mutex;

} NameServerState;

#endif // NM_STRUCTS_H

