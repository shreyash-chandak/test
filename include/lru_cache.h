#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include "ts_hashmap.h"
#include <pthread.h>

// A node in the doubly-linked list
typedef struct CacheNode {
    char* key;
    void* value;
    struct CacheNode* prev;
    struct CacheNode* next;
} CacheNode;

// The main cache struct
typedef struct {
    TSHashMap* map;
    CacheNode* head;
    CacheNode* tail;
    int size;
    int capacity;
    pthread_mutex_t lock;
} LRUCache;

/**
 * @brief Creates a new LRU cache with the given capacity.
 */
LRUCache* lru_cache_create(int capacity);

/**
 * @brief Destroys the LRU cache, freeing all internal nodes.
 * Does NOT free the 'value' pointers it stores.
 */
void lru_cache_destroy(LRUCache* cache);

/**
 * @brief Gets a value from the cache.
 * This is thread-safe. Moves the item to the front if found.
 * @return The value, or NULL if not found.
 */
void* lru_cache_get(LRUCache* cache, const char* key);

/**
 * @brief Puts a value into the cache.
 * This is thread-safe. Moves the item to the front.
 * Evicts the LRU item if capacity is exceeded.
 */
void lru_cache_put(LRUCache* cache, const char* key, void* value);

/**
 * @brief Removes a value from the cache.
 * Used when a file is deleted to prevent stale cache entries.
 */
void* lru_cache_remove(LRUCache* cache, const char* key);

#endif // LRU_CACHE_H