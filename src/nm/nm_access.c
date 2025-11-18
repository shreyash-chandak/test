#include "nm_access.h"
#include "nm_structs.h"
#include "utils.h"
#include "common.h"
#include "nm_persistence.h"
#include "lru_cache.h"

// --- Helper for LISTREQS ---
typedef struct { char* buf; int* len; size_t max_len; int count; } ListReqsArgs;
static void append_req_entry(const char* key, void* value, void* arg) {
    ListReqsArgs* args = (ListReqsArgs*)arg;
    args->count++;
    *(args->len) += snprintf(args->buf + *(args->len), args->max_len - *(args->len),
        "  - User '%s' is requesting access.\n", key);
}

/**
 * @brief Handles a client's request to REQACCESS
 */
void handle_reqaccess(uint32_t client_id, int sock, 
                      Payload_FileRequest* payload, NameServerState* state) {
    FileMetadata* meta = (FileMetadata*)lru_cache_get(state->file_cache, payload->filename);
    if (meta == NULL) {
        meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename);
        if (meta != NULL) {
            lru_cache_put(state->file_cache, payload->filename, meta);
        }
    }
    const char* username = get_username_from_id(state, client_id);

    if (meta == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_REQACCESS_REQ, ERR_FILE_NOT_FOUND, "File not found.");
        return;
    }
    if (username == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_REQACCESS_REQ, ERR_UNKNOWN, "Internal server error: Client session not found.");
        return;
    }

    if (strcmp(username, meta->owner_username) == 0) {
        send_nm_error_response(sock, client_id, OP_CLIENT_REQACCESS_REQ, ERR_INVALID_COMMAND, "You are the owner.");
        return;
    }
    if (check_access(meta, username, PERM_READ)) {
        send_nm_error_response(sock, client_id, OP_CLIENT_REQACCESS_REQ, ERR_INVALID_COMMAND, "You already have access.");
        return;
    }

    pthread_mutex_lock(&meta->meta_lock);
    if (ts_hashmap_get(meta->pending_requests, username) != NULL) {
        pthread_mutex_unlock(&meta->meta_lock);
        send_nm_error_response(sock, client_id, OP_CLIENT_REQACCESS_REQ, ERR_ALREADY_ACTIVE, "Request already pending.");
        return;
    }
    ts_hashmap_put(meta->pending_requests, username, (void*)1);
    pthread_mutex_unlock(&meta->meta_lock);

    persistence_log_op("META,REQACCESS,%s,%s\n", payload->filename, username);

    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_REQACCESS_RES;
    res_header.length = sizeof(MsgHeader);
    send_message(sock, &res_header, NULL);
}

/**
 * @brief Handles a client's request to LISTREQS
 */
void handle_listreqs(uint32_t client_id, int sock, 
                     Payload_FileRequest* payload, NameServerState* state) {
    FileMetadata* meta = (FileMetadata*)lru_cache_get(state->file_cache, payload->filename);
    if (meta == NULL) {
        meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename);
        if (meta != NULL) {
            lru_cache_put(state->file_cache, payload->filename, meta);
        }
    }
    const char* username = get_username_from_id(state, client_id);

    if (meta == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_LISTREQS_REQ, ERR_FILE_NOT_FOUND, "File not found.");
        return;
    }
    if (username == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_LISTREQS_REQ, ERR_UNKNOWN, "Internal server error: Client session not found.");
        return;
    }

    if (strcmp(username, meta->owner_username) != 0) {
        send_nm_error_response(sock, client_id, OP_CLIENT_LISTREQS_REQ, ERR_ACCESS_DENIED, "You are not the owner.");
        return;
    }

    MsgPayload res_payload = {0};
    int len = 0;
    char* buffer = res_payload.generic.buffer;
    ListReqsArgs args = { buffer, &len, MAX_BUFFER_LEN, 0 };

    len += snprintf(buffer, MAX_BUFFER_LEN, "Pending requests for '%s':\n", payload->filename);
    pthread_mutex_lock(&meta->meta_lock);
    ts_hashmap_iterate(meta->pending_requests, append_req_entry, &args);
    pthread_mutex_unlock(&meta->meta_lock);

    if (args.count == 0) {
        len += snprintf(buffer + len, MAX_BUFFER_LEN - len, "  (No pending requests)\n");
    }

    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_LISTREQS_RES;
    res_header.length = sizeof(MsgHeader) + len;
    send_message(sock, &res_header, &res_payload);
}

/**
 * @brief Handles a client's request to APPROVE/DENY
 */
void handle_approve(uint32_t client_id, int sock, 
                    Payload_ClientAccessReq* payload, NameServerState* state) {
    FileMetadata* meta = (FileMetadata*)lru_cache_get(state->file_cache, payload->filename);
    if (meta == NULL) {
        meta = (FileMetadata*)ts_hashmap_get(state->file_metadata_map, payload->filename);
        if (meta != NULL) {
            lru_cache_put(state->file_cache, payload->filename, meta);
        }
    }
    const char* owner_username = get_username_from_id(state, client_id);

    if (meta == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_APPROVE_REQ, ERR_FILE_NOT_FOUND, "File not found.");
        return;
    }
    if (owner_username == NULL) {
        send_nm_error_response(sock, client_id, OP_CLIENT_APPROVE_REQ, ERR_UNKNOWN, "Internal server error: Client session not found.");
        return;
    }

    if (strcmp(owner_username, meta->owner_username) != 0) {
        send_nm_error_response(sock, client_id, OP_CLIENT_APPROVE_REQ, ERR_ACCESS_DENIED, "You are not the owner.");
        return;
    }

    const char* target_user = payload->username;
    pthread_mutex_lock(&meta->meta_lock);

    void* request = ts_hashmap_remove(meta->pending_requests, target_user);
    if (request == NULL) {
        pthread_mutex_unlock(&meta->meta_lock);
        send_nm_error_response(sock, client_id, OP_CLIENT_APPROVE_REQ, ERR_USER_NOT_FOUND, "No pending request found for this user.");
        return;
    }

    persistence_log_op("META,REMREQ,%s,%s\n", payload->filename, target_user);

    if (payload->flags & ACCESS_FLAG_REMOVE) {
        // This is a DENY. We just removed the request.
        pthread_mutex_unlock(&meta->meta_lock);
    } else {
        // This is an APPROVE. Add them to the real ACL.
        const char* level = (payload->flags & ACCESS_FLAG_WRITE_ADD) ? "RW" : "R";
        char* level_alloc = strdup(level);

        void* old_level = ts_hashmap_remove(meta->access_list, target_user);
        if (old_level) free(old_level);
        ts_hashmap_put(meta->access_list, target_user, (void*)level_alloc);

        persistence_log_op("META,ADDACCESS,%s,%s,%s\n", payload->filename, target_user, level);
        pthread_mutex_unlock(&meta->meta_lock);
    }

    MsgHeader res_header = {0};
    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_NM_APPROVE_RES;
    res_header.length = sizeof(MsgHeader);
    send_message(sock, &res_header, NULL);
}