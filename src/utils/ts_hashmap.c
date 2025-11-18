#include "ts_hashmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// djb2 hash function
static unsigned long hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

TSHashMap* ts_hashmap_create() {
    TSHashMap* map = malloc(sizeof(TSHashMap));
    if (!map) return NULL;

    map->size = HASHMAP_INIT_SIZE;
    map->item_count = 0;
    map->buckets = calloc(map->size, sizeof(HashMapEntry*));
    if (!map->buckets) {
        free(map);
        return NULL;
    }

    map->bucket_locks = malloc(sizeof(pthread_mutex_t) * map->size);
    if (!map->bucket_locks) {
        free(map->buckets);
        free(map);
        return NULL;
    }

    for (size_t i = 0; i < map->size; i++) {
        pthread_mutex_init(&map->bucket_locks[i], NULL);
    }
    
    return map;
}

void ts_hashmap_destroy(TSHashMap* map, void (*free_value)(void*)) {
    if (!map) return;
    for (size_t i = 0; i < map->size; i++) {
        HashMapEntry* entry = map->buckets[i];
        while (entry) {
            HashMapEntry* next = entry->next;
            free(entry->key);
            if (free_value) {
                free_value(entry->value);
            }
            free(entry);
            entry = next;
        }
        pthread_mutex_destroy(&map->bucket_locks[i]);
    }
    free(map->bucket_locks);
    free(map->buckets);
    free(map);
}

static size_t get_bucket_index(TSHashMap* map, const char* key) {
    return hash(key) % map->size;
}

void ts_hashmap_put(TSHashMap* map, const char* key, void* value) {
    size_t index = get_bucket_index(map, key);
    
    pthread_mutex_lock(&map->bucket_locks[index]);

    HashMapEntry* entry = map->buckets[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            // Key already exists, update value
            // Note: We don't free the old value, caller must handle it
            entry->value = value;
            pthread_mutex_unlock(&map->bucket_locks[index]);
            return;
        }
        entry = entry->next;
    }

    // Key doesn't exist, create new entry
    HashMapEntry* new_entry = malloc(sizeof(HashMapEntry));
    new_entry->key = strdup(key);
    new_entry->value = value;
    new_entry->next = map->buckets[index];
    
    map->buckets[index] = new_entry;
    map->item_count++;
    
    pthread_mutex_unlock(&map->bucket_locks[index]);
    
    // TODO: Add resize logic if item_count > size * 0.75
}

void* ts_hashmap_get(TSHashMap* map, const char* key) {
    size_t index = get_bucket_index(map, key);
    void* value = NULL;

    pthread_mutex_lock(&map->bucket_locks[index]);

    HashMapEntry* entry = map->buckets[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            value = entry->value;
            break;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&map->bucket_locks[index]);
    return value;
}

void* ts_hashmap_remove(TSHashMap* map, const char* key) {
    size_t index = get_bucket_index(map, key);
    void* value = NULL;

    pthread_mutex_lock(&map->bucket_locks[index]);

    HashMapEntry* entry = map->buckets[index];
    HashMapEntry* prev = NULL;

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                map->buckets[index] = entry->next;
            }
            value = entry->value;
            free(entry->key);
            free(entry);
            map->item_count--;
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&map->bucket_locks[index]);
    return value;
}

void ts_hashmap_iterate(TSHashMap* map, 
                        void (*callback)(const char* key, void* value, void* arg), 
                        void* arg) {
    if (!map || !callback) return;

    // We must lock *all* buckets to do a safe iteration.
    // A more complex implementation might lock one by one,
    // but this is safer for now.
    for (size_t i = 0; i < map->size; i++) {
        pthread_mutex_lock(&map->bucket_locks[i]);
    }

    // Now that all buckets are locked, we can iterate
    for (size_t i = 0; i < map->size; i++) {
        HashMapEntry* entry = map->buckets[i];
        while (entry) {
            callback(entry->key, entry->value, arg);
            entry = entry->next;
        }
    }
    
    // Unlock all buckets in reverse
    for (size_t i = 0; i < map->size; i++) {
        pthread_mutex_unlock(&map->bucket_locks[i]);
    }
}