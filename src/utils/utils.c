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

