#ifndef TS_HASHMAP_H
#define TS_HASHMAP_H

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>

#define HASHMAP_INIT_SIZE 16384

// Entry in the hashmap (for chaining)
typedef struct HashMapEntry {
    char* key;
    void* value;
    struct HashMapEntry* next;
} HashMapEntry;

// The main hashmap structure
typedef struct {
    HashMapEntry** buckets;
    size_t size;
    size_t item_count;
    pthread_mutex_t* bucket_locks; // Fine-grained locking per bucket
} TSHashMap;

/**
 * @brief Creates a new thread-safe hashmap.
 * @return A pointer to the new TSHashMap, or NULL on failure.
 */
TSHashMap* ts_hashmap_create();

/**
 * @brief Destroys a hashmap.
 * @param map The hashmap to destroy.
 * @param free_value A function pointer to free the stored value (or NULL).
 */
// --- THIS IS THE FIX for 'too many arguments' ---
// The implementation took two args, the header only took one.
void ts_hashmap_destroy(TSHashMap* map, void (*free_value)(void*));

/**
 * @brief Inserts a key-value pair. Replaces if key exists.
 * @param map The hashmap.
 * @param key The null-terminated string key.
 * @param value The pointer to the value.
 */
void ts_hashmap_put(TSHashMap* map, const char* key, void* value);

/**
 * @brief Retrieves a value by its key.
 * @param map The hashmap.
 * @param key The null-terminated string key.
 * @return The value pointer, or NULL if not found.
 */
void* ts_hashmap_get(TSHashMap* map, const char* key);

/**
 * @brief Removes a key-value pair from the hashmap.
 * @param map The hashmap.
 * @param key The null-terminated string key.
 * @return The value (so you can free it), or NULL if not found.
 */
void* ts_hashmap_remove(TSHashMap* map, const char* key);

/**
 * @brief Iterates over all key-value pairs in the map.
 * @param map The hashmap.
 * @param callback The function to call for each item.
 * @param arg A generic pointer to pass to the callback (e.g., a buffer)
 */
void ts_hashmap_iterate(TSHashMap* map, 
                        void (*callback)(const char* key, void* value, void* arg), 
                        void* arg);

#endif // TS_HASHMAP_H

