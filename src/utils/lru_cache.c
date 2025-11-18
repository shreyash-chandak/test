#include "lru_cache.h"
#include "common.h" 

// Creates a new, isolated node
static CacheNode* _create_node(const char* key, void* value) {
    CacheNode* node = (CacheNode*)malloc(sizeof(CacheNode));
    node->key = strdup(key);
    node->value = value;
    node->prev = NULL;
    node->next = NULL;
    return node;
}

// Removes a node from the linked list
static void _remove_node(LRUCache* cache, CacheNode* node) {
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        cache->head = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    } else {
        cache->tail = node->prev;
    }
}

// Adds a node to the front (head) of the linked list
static void _add_to_front(LRUCache* cache, CacheNode* node) {
    node->next = cache->head;
    node->prev = NULL;
    if (cache->head) {
        cache->head->prev = node;
    }
    cache->head = node;
    if (cache->tail == NULL) {
        cache->tail = node;
    }
}

// --- Public API Functions (Thread-safe) ---

LRUCache* lru_cache_create(int capacity) {
    LRUCache* cache = (LRUCache*)malloc(sizeof(LRUCache));
    cache->map = ts_hashmap_create();
    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;
    cache->capacity = capacity;
    pthread_mutex_init(&cache->lock, NULL);
    return cache;
}

void lru_cache_destroy(LRUCache* cache) {
    // We don't need to lock, this is a final teardown
    // Free all list nodes
    CacheNode* node = cache->head;
    while (node) {
        CacheNode* next = node->next;
        free(node->key);
        free(node);
        node = next;
    }
    // Destroy the map (it only holds pointers to nodes, so no value-free function)
    ts_hashmap_destroy(cache->map, NULL);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

void* lru_cache_get(LRUCache* cache, const char* key) {
    pthread_mutex_lock(&cache->lock);

    CacheNode* node = (CacheNode*)ts_hashmap_get(cache->map, key);
    if (node == NULL) {
        // Cache Miss
        pthread_mutex_unlock(&cache->lock);
        return NULL;
    }

    // Cache Hit: Move this node to the front
    _remove_node(cache, node);
    _add_to_front(cache, node);

    pthread_mutex_unlock(&cache->lock);
    return node->value;
}

void lru_cache_put(LRUCache* cache, const char* key, void* value) {
    pthread_mutex_lock(&cache->lock);

    CacheNode* node = (CacheNode*)ts_hashmap_get(cache->map, key);

    if (node != NULL) {
        // --- Hit (Update) ---
        // Value already exists. Update it and move to front.
        node->value = value;
        _remove_node(cache, node);
        _add_to_front(cache, node);
    } else {
        // --- Miss (Insert) ---
        if (cache->size >= cache->capacity) {
            // Evict LRU (tail)
            CacheNode* lru_node = cache->tail;
            if (lru_node) {
                _remove_node(cache, lru_node);
                ts_hashmap_remove(cache->map, lru_node->key);
                free(lru_node->key);
                free(lru_node);
                cache->size--;
            }
        }
        
        // Add new node to front
        node = _create_node(key, value);
        _add_to_front(cache, node);
        ts_hashmap_put(cache->map, key, node);
        cache->size++;
    }

    pthread_mutex_unlock(&cache->lock);
}

void* lru_cache_remove(LRUCache* cache, const char* key) {
    pthread_mutex_lock(&cache->lock);

    CacheNode* node = (CacheNode*)ts_hashmap_remove(cache->map, key);
    if (node == NULL) {
        pthread_mutex_unlock(&cache->lock);
        return NULL;
    }

    // Remove from linked list
    _remove_node(cache, node);
    cache->size--;

    void* value = node->value; // Save value to return
    free(node->key);
    free(node);

    pthread_mutex_unlock(&cache->lock);
    return value;
}