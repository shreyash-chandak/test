#ifndef UTILS_H
#define UTILS_H

#include "protocol.h"
#include <pthread.h>

void init_printf_mutex();
void destroy_printf_mutex();
void safe_printf(const char* format, ...);

// --- Networking Functions ---

int send_message(int sock, MsgHeader* header, MsgPayload* payload);
int recv_message(int sock, MsgHeader* header, MsgPayload* payload);
uint32_t compute_checksum(const void* data, size_t length);

#endif
