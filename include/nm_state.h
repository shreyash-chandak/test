#ifndef NM_STATE_H
#define NM_STATE_H

#include "protocol.h"
#include "nm_structs.h"

/**
 * @brief Handles the full registration logic for a new client.
 * Allocates a new ClientInfo struct and adds it to the state maps.
 * * @param sock The client's socket.
 * @param payload The received OP_CLIENT_REGISTER_REQ payload.
 * @param state The global server state.
 * @return The new client_id, or 0 on failure.
 */
uint32_t register_client(int sock, Payload_ClientRegisterReq* payload, NameServerState* state, ErrorCode* err_code);

/**
 * @brief Handles the full registration logic for a new Storage Server.
 * Allocates a new StorageServerInfo struct and adds it to the state maps.
 * * @param sock The SS's socket.
 * @param payload The received OP_SS_REGISTER_REQ payload.
 * @param state The global server state.
 * @return The new ss_id, or 0 on failure.
 */
uint32_t register_ss(int sock, Payload_SSRegisterReq* payload, NameServerState* state);

/**
 * @brief Cleans up all state associated with a disconnected socket.
 * Finds the client_id or ss_id from the socket, then removes
 * the corresponding entries from all maps.
 * * @param sock The socket that disconnected.
 * @param state The global server state.
 */
void handle_disconnect(int sock, NameServerState* state);

#endif // NM_STATE_H
