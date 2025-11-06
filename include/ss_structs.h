#ifndef SS_STRUCTS_H
#define SS_STRUCTS_H

#include <pthread.h>
#include <stdint.h>
#include "protocol.h"
#include "ts_hashmap.h" // <-- THE MISSING INCLUDE

// --- Concurrency Structs for File Locking ---
// (This is the complex, correct model)

// Represents a single locked sentence
typedef struct {
    pthread_mutex_t mutex; // A dedicated mutex for this sentence
    uint32_t client_id;    // Which client has it locked
    int lock_count;        // (For recursive locks, if needed)
} SentenceLock;

// Represents all locks for a single file
typedef struct {
    // A lock to protect the 'sentence_locks' map itself
    // (for adding/removing sentences)
    pthread_mutex_t map_mutex;
    
    // A map of: (int sentence_index) -> (SentenceLock* lock)
    TSHashMap* sentence_locks;

    // A Read-Write lock for the file *content*
    // - READ (read, stream) takes a Read lock.
    // - WRITE (ETIRW) takes a Write lock.
    pthread_rwlock_t content_rw_lock;
} FileLockInfo;


// --- Main State Struct ---

typedef struct {
    char data_dir[MAX_PATH_LEN];
    int nm_socket_fd;
    int client_socket_fd; // The listening socket for clients
    uint32_t ss_id;

    // --- FIELDS ADDED TO FIX COMPILE ERROR ---
    char nm_ip[MAX_IP_LEN];
    char public_ip[MAX_IP_LEN];
    uint16_t nm_port;
    uint16_t client_port;
    // -----------------------------------------

    // Map of: (char* filename) -> (FileLockInfo* info)
    // This manages all concurrency for all files on this SS.
    TSHashMap* file_lock_map;

} StorageServerState;


#endif // SS_STRUCTS_H

