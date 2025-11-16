#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>     // For va_list, va_start, va_end
#include <netinet/in.h> // For htonl, ntohl
#include <sys/socket.h> // For send/recv

// --- Global printf mutex ---
static pthread_mutex_t printf_mutex;

void init_printf_mutex() {
    pthread_mutex_init(&printf_mutex, NULL);
}

void destroy_printf_mutex() {
    pthread_mutex_destroy(&printf_mutex);
}

// Thread-safe printf
void safe_printf(const char* format, ...) {
    pthread_mutex_lock(&printf_mutex);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout); // Ensure it prints immediately
    pthread_mutex_unlock(&printf_mutex);
}


// --- Checksum ---
uint32_t compute_checksum(const void* data, size_t length) {
    // Simple additive checksum for now.
    // TODO: Replace with CRC32 for a real project.
    uint32_t sum = 0;
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < length; ++i) {
        sum += p[i];
    }
    return sum;
}


// --- Networking Functions ---

/**
 * @brief Helper function to send a full buffer.
 * Handles short sends.
 */
static int send_all(int sock, const void* buffer, size_t length) {
    const char* ptr = (const char*)buffer;
    while (length > 0) {
        int bytes_sent = send(sock, ptr, length, 0);
        if (bytes_sent < 0) {
            perror("send failed");
            return -1; // Send failure
        }
        if (bytes_sent == 0) {
            return -1; // Socket closed
        }
        ptr += bytes_sent;
        length -= bytes_sent;
    }
    return 0; // Success
}

/**
 * @brief Helper function to receive a full buffer.
 * Handles short receives.
 */
static int recv_all(int sock, void* buffer, size_t length) {
    char* ptr = (char*)buffer;
    while (length > 0) {
        int bytes_recv = recv(sock, ptr, length, 0);
        if (bytes_recv < 0) {
            perror("recv failed");
            return -1; // Recv failure
        }
        if (bytes_recv == 0) {
            return 0; // Connection closed gracefully
        }
        ptr += bytes_recv;
        length -= bytes_recv;
    }
    return 1; // Success
}

void send_nm_error_response(int sock, uint32_t client_id, OpCode original_opcode, 
                          ErrorCode error, const char* message) {
    

    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};

    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_ERROR_RES;
    res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error); 
    res_header.client_id = client_id; // <-- Use the client_id
    res_header.error = error;
    
    strncpy(res_payload.error.message, message, MAX_ERROR_MSG_LEN - 1);
    res_payload.error.message[MAX_ERROR_MSG_LEN - 1] = '\0';
    
    send_message(sock, &res_header, &res_payload); 
}

// too lazy to merge these two into the above better function

void send_nm_error(int sock, ErrorCode error, const char* message) {
    MsgHeader res_header = {0};
    MsgPayload res_payload = {0};

    res_header.version = PROTOCOL_VERSION;
    res_header.opcode = OP_ERROR_RES;
    res_header.error = error;
    res_header.length = sizeof(MsgHeader) + sizeof(Payload_Error);
    
    strncpy(res_payload.error.message, message, MAX_ERROR_MSG_LEN - 1);
    res_payload.error.message[MAX_ERROR_MSG_LEN - 1] = '\0';
    
    send_message(sock, &res_header, &res_payload);
}

static const char* get_permission_string(FileMetadata* meta, const char* username) {
    // ts_hashmap_get is thread-safe for reading.
    return (const char*)ts_hashmap_get(meta->access_list, username);
}

// The main access control check.
bool check_access(FileMetadata* meta, const char* username, PermissionLevel required_level) {
    
    // 1. Check if they are the owner.
    // The owner always has both read and write access.
    if (strcmp(username, meta->owner_username) == 0) {
        return true;
    }

    // 2. Look up the *specific user's* permission
    const char* user_permission = get_permission_string(meta, username);

    // 3. Handle READ requests
    if (required_level == PERM_READ) {
        
        // A. Check if the specific user has R or RW
        if (user_permission != NULL && (strcmp(user_permission, "R") == 0 || strcmp(user_permission, "RW") == 0)) {
            return true;
        }
        // If user-specific check fails, check for public "everyone" access
        const char* public_permission = get_permission_string(meta, "unregistered");
        if (public_permission != NULL && (strcmp(public_permission, "R") == 0 || strcmp(public_permission, "RW") == 0)){
            return true;
        }
        // If both checks fail, deny read
        return false;
    }

    // 4. Handle WRITE requests
    if (required_level == PERM_WRITE) {
        // "unknown" does NOT grant write access.
        return (user_permission != NULL && strcmp(user_permission, "RW") == 0);
    }
    
    return false; // Default deny
}



const char* get_username_from_id(NameServerState* state, uint32_t client_id) {
    
    // Create a string key for the ID
    char id_key[16];
    snprintf(id_key, 16, "%u", client_id);

    // Look up in the client_id_map
    ClientInfo* client = (ClientInfo*)ts_hashmap_get(state->client_id_map, id_key);
    
    if (client) {
        return client->username;
    }
    
    return NULL;
}


/**
 * @brief Main function to send a protocol message.
 * Serializes, checksums, and handles byte order.
 */
int send_message(int sock, MsgHeader* header, MsgPayload* payload) {
    size_t payload_len = header->length - sizeof(MsgHeader);

    // 1. Create a temporary header for network byte order
    MsgHeader net_header;
    net_header.version = htons(header->version);
    net_header.opcode = htons((uint16_t)header->opcode);
    net_header.length = htonl(header->length);
    net_header.client_id = htonl(header->client_id);
    net_header.error = htonl((uint32_t)header->error);
    net_header.reserved = htonl(header->reserved);
    
    // 2. Compute checksum *before* putting it in the header
    if (payload_len > 0) {
        header->checksum = compute_checksum(payload, payload_len);
    } else {
        header->checksum = 0;
    }
    net_header.checksum = htonl(header->checksum);

    // 3. Send header
    if (send_all(sock, &net_header, sizeof(MsgHeader)) != 0) {
        safe_printf("Failed to send message header\n");
        return -1;
    }

    // 4. Send payload (if any)
    if (payload_len > 0) {
        if (send_all(sock, payload, payload_len) != 0) {
            safe_printf("Failed to send message payload\n");
            return -1;
        }
    }
    return 0; // Success
}

/**
 * @brief Main function to receive a protocol message.
 * Deserializes, validates, and handles byte order.
 */
int recv_message(int sock, MsgHeader* header, MsgPayload* payload) {
    // 1. Receive header
    MsgHeader net_header;
    int header_recv = recv_all(sock, &net_header, sizeof(MsgHeader));
    
    if (header_recv <= 0) {
        return header_recv; // 0 for disconnect, -1 for error
    }

    // 2. Convert header from network to host byte order
    header->version = ntohs(net_header.version);
    header->opcode = (OpCode)ntohs(net_header.opcode);
    header->length = ntohl(net_header.length);
    header->client_id = ntohl(net_header.client_id);
    header->error = (ErrorCode)ntohl(net_header.error);
    header->checksum = ntohl(net_header.checksum);
    header->reserved = ntohl(net_header.reserved);

    // 3. Basic validation
    if (header->version != PROTOCOL_VERSION) {
        safe_printf("Invalid protocol version: %u\n", header->version);
        return -1;
    }
    if (header->length < sizeof(MsgHeader)) {
        safe_printf("Invalid packet length: %u\n", header->length);
        return -1;
    }

    // 4. Receive payload (if any)
    size_t payload_len = header->length - sizeof(MsgHeader);
    if (payload_len > 0) {
        if (payload_len > sizeof(MsgPayload)) {
            safe_printf("Payload length %zu exceeds max %zu\n", payload_len, sizeof(MsgPayload));
            return -1;
        }
        
        int payload_recv = recv_all(sock, payload, payload_len);
        if (payload_recv <= 0) {
            return payload_recv; // Disconnect or error
        }

        // 5. Verify checksum
        uint32_t expected_checksum = compute_checksum(payload, payload_len);
        if (header->checksum != expected_checksum) {
            safe_printf("Checksum mismatch! Got %u, expected %u\n", header->checksum, expected_checksum);
            return -1;
        }
    }

    return 1; // Success
}

