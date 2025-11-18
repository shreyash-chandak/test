#ifndef SS_WRITE_HELPERS_H
#define SS_WRITE_HELPERS_H

#include "ss_structs.h"

/**
 * @brief Handles a client's WRITE_START request.
 * Acquires a sentence lock and creates a new write session.
 * @param out_session A pointer that will be populated with the new session.
 */
void handle_ss_write_start(StorageServerState* state, int client_sock, 
                           uint32_t client_id, Payload_ClientSSWriteStart* payload,
                           WriteSession** out_session);

/**
 * @brief Handles a client's WRITE_DATA packet.
 * Buffers the change into the session.
 */
void handle_ss_write_data(WriteSession* session, Payload_ClientSSWriteData* payload);

/**
 * @brief Handles a client's ETIRW (commit) request.
 * Applies buffered changes to the file, creates .bak, and releases locks.
 * @return 0 on success, -1 on failure.
 */
int handle_ss_etirw(StorageServerState* state, WriteSession* session);

/**
 * @brief Helper to send a simple SS-side error response.
 */
void send_ss_error(int sock, ErrorCode error, const char* message);

/**
 * @brief Helper to free a WriteSession and all its associated operations.
 */
void free_write_session(WriteSession* session);

/**
 * @brief Cleans up an abandoned write session (e.g., on client disconnect).
 * This finds the sentence lock held by the session and releases it.
 */
void handle_ss_write_cleanup(StorageServerState* state, WriteSession* session);

uint32_t get_sentence_count(StorageServerState* state, const char* filename);
int apply_changes_to_file(StorageServerState* state, WriteSession* session, 
                            const char* tmp_path, const char* final_path);

#endif // SS_WRITE_HELPERS_H