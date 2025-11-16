#ifndef CLIENT_REPL_H
#define CLIENT_REPL_H

#include <stdint.h> // For uint32_t
extern uint32_t my_client_id;

void start_reply(int nm_socket);
extern char username[MAX_USERNAME_LEN];

#endif
