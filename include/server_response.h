#ifndef SERVER_RESPONSE_H
#define SERVER_RESPONSE_H

#include "protocol.h"
#include "parse_command.h" 
// We need ParsedCommand for context

/**
 * @brief Main router for handling all responses from the Name Server.
 * Dispatches to other functions based on opcode.
 * @param header The response header from the NM.
 * @param payload The response payload from the NM.
 * @param original_cmd The client's original command (needed for SS redirects).
 */
void handle_server_response(MsgHeader* header, MsgPayload* payload, ParsedCommand* original_cmd);

#endif // SERVER_RESPONSE_H