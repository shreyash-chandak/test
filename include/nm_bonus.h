#ifndef NM_BONUS_H
#define NM_BONUS_H

#include "protocol.h"
#include "nm_structs.h"


void handle_reqaccess(uint32_t client_id, int sock, 
                      Payload_FileRequest* payload, NameServerState* state);


void handle_listreqs(uint32_t client_id, int sock, 
                     Payload_FileRequest* payload, NameServerState* state);

void handle_approve(uint32_t client_id, int sock, 
                    Payload_ClientAccessReq* payload, NameServerState* state);


#endif