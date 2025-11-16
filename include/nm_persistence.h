#ifndef NM_PERSISTENCE_H
#define NM_PERSISTENCE_H

#include "nm_structs.h"

/**
 * @brief Initializes the logging system (mutexes, directories).
 */
void persistence_init(void);

/**
 * @brief Cleans up the logging system on shutdown.
 */
void persistence_destroy(void);

/**
 * @brief Loads all users and metadata from logs into the in-memory state.
 * This is called once on Name Server startup.
 * @param state The main NameServerState to populate.
 */
void persistence_load_state(NameServerState* state);
void free_file_metadata(void* val);
/**
 * @brief Appends a single operation to the appropriate log file.
 * This is the "one function" you'll call after a hashmap change.
 *
 * @param format A printf-style format string.
 * Must start with "USER," or "META," to route to the correct log.
 * @param ... The arguments for the format string.
 *
 * @example
 * persistence_log_op("USER,%s,%s", username, password);
 * persistence_log_op("META,CREATE,%s,%s", filename, owner);
 */
void persistence_log_op(const char* format, ...);

#endif // NM_PERSISTENCE_H