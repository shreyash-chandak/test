#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <assert.h> // For static_assert
// For htonl, ntohl, etc.
#include <arpa/inet.h> 

// --- Tunable Constants -----------------------------------------------------
#define MAX_FILENAME_LEN 256
#define MAX_USERNAME_LEN 128
#define MAX_PASSWORD_LEN 128
#define MAX_PATH_LEN 1024
#define MAX_IP_LEN 46          // Enough for IPv6
#define MAX_WRITE_CONTENT_LEN 128 // Max size of a single word-insert
#define MAX_BUFFER_LEN 4096    // General purpose buffer for strings, file chunks
#define MAX_ERROR_MSG_LEN 256
#define PROTOCOL_VERSION 0x01  // Our first version

// --- Core Opcodes (Message Types) 

typedef enum {
    // --- System & Registration ---
    OP_CLIENT_REGISTER_REQ,   // Client -> NM: "I am user X"
    OP_CLIENT_REGISTER_RES,   // NM -> Client: "OK, you are client_id Y"
    OP_SS_REGISTER_REQ,       // SS -> NM: "I am online at ip:port, I have files..."
    OP_SS_REGISTER_RES,       // NM -> Client: "OK, you are ss_id Z"

    // --- P2 (Systems) Features (NM-Handled) ---
    OP_CLIENT_VIEW_REQ,       // Client -> NM: "VIEW -al"
    OP_NM_VIEW_RES,           // NM -> Client: "Here is the formatted string..."
    OP_CLIENT_CREATE_REQ,     // Client -> NM: "CREATE file.txt"
    OP_NM_CREATE_RES,         // NM -> Client: "OK" or "Error"
    OP_CLIENT_DELETE_REQ,     // Client -> NM: "DELETE file.txt"
    OP_NM_DELETE_RES,         // NM -> Client: "OK" or "Error"
    OP_CLIENT_INFO_REQ,       // Client -> NM: "INFO file.txt"
    OP_NM_INFO_RES,           // NM -> Client: "Here is the info string..."
    OP_CLIENT_LIST_REQ,       // Client -> NM: "LIST"
    OP_NM_LIST_RES,           // NM -> Client: "Here are the users..."
    OP_CLIENT_ACCESS_REQ,     // Client -> NM: "ADDACCESS -W file.txt user2"
    OP_NM_ACCESS_RES,         // NM -> Client: "OK" or "Error"

    // --- P1 (Editor) Features (3-Way Handshake) ---
    OP_CLIENT_READ_REQ,       // Client -> NM: "READ file.txt"
    OP_NM_READ_RES,           // NM -> Client: "OK, go to SS at ip:port"
    OP_CLIENT_SS_READ_REQ,    // Client -> SS: "READ file.txt" (The *real* request)
    OP_SS_CLIENT_READ_RES,    // SS -> Client: (Sends file data)
    
    OP_CLIENT_STREAM_REQ,     // Client -> NM: "STREAM file.txt"
    OP_NM_STREAM_RES,         // NM -> Client: "OK, go to SS at ip:port"
    OP_CLIENT_SS_STREAM_REQ,  // Client -> SS: "STREAM file.txt"
    OP_SS_CLIENT_STREAM_DATA, // SS -> Client: "Here is a word..." (Sent multiple times)
    OP_SS_CLIENT_STREAM_END,  // SS -> Client: "All done streaming."

    OP_CLIENT_UNDO_REQ,       // Client -> NM: "UNDO file.txt"
    OP_NM_UNDO_RES,           // NM -> Client: "OK, go to SS at ip:port"
    OP_CLIENT_SS_UNDO_REQ,    // Client -> SS: "UNDO file.txt"
    OP_SS_CLIENT_UNDO_RES,    // SS -> Client: "OK, it is undone."

    // --- P1/P2 Monster: WRITE Flow (Multi-Stage) ---
    // STEP 1: Client asks NM for permission and location
    OP_CLIENT_WRITE_REQ,      // Client -> NM: "I want to WRITE file.txt sent 5"
    OP_NM_WRITE_RES,          // NM -> Client: "OK, go to SS at ip:port"
    // STEP 2: Client contacts SS to start the session
    OP_CLIENT_SS_WRITE_START, // Client -> SS: "Starting WRITE on file.txt sent 5"
    OP_SS_CLIENT_WRITE_START_RES, // SS -> Client: "OK, sentence is locked" or "ERR_SENTENCE_LOCKED"
    // STEP 3: Client sends data (multiple times)
    OP_CLIENT_SS_WRITE_DATA,  // Client -> SS: "At word 2, insert 'hello'"
    // STEP 4: Client commits
    OP_CLIENT_SS_ETIRW,       // Client -> SS: "I'm done. ETIRW."
    OP_SS_CLIENT_ETIRW_RES,   // SS -> Client: "OK, saved and unlocked."
    
    OP_SS_NM_WRITE_COMPLETE,    // metadata needs update
    OP_SS_NM_UNDO_COMPLETE,

    // --- REDO ---
    OP_CLIENT_REDO_REQ,
    OP_NM_REDO_RES,
    OP_CLIENT_SS_REDO_REQ,
    OP_SS_CLIENT_REDO_RES,
    OP_SS_NM_REDO_COMPLETE,

    // --- CHECKPOINTS ---
    OP_CLIENT_CHECKPOINT_REQ,
    OP_NM_CHECKPOINT_RES,
    OP_CLIENT_SS_CHECKPOINT_REQ,
    OP_SS_CLIENT_CHECKPOINT_RES,

    OP_CLIENT_REVERT_REQ,
    OP_NM_REVERT_RES,
    OP_CLIENT_SS_REVERT_REQ,
    OP_SS_CLIENT_REVERT_RES,
    OP_SS_NM_REVERT_COMPLETE,

    OP_CLIENT_VIEWCHECKPOINT_REQ,
    OP_NM_VIEWCHECKPOINT_RES,
    OP_CLIENT_SS_VIEWCHECKPOINT_REQ,
    // (Uses OP_SS_CLIENT_READ_RES for data)

    OP_CLIENT_LISTCHECKPOINTS_REQ,
    OP_NM_LISTCHECKPOINTS_RES,
    OP_CLIENT_SS_LISTCHECKPOINTS_REQ,
    OP_SS_CLIENT_LISTCHECKPOINTS_RES,

    // --- REPLICATION ---
    OP_NM_SS_REPLICATE_REQ,     // NM -> Secondary SS (Async)
    OP_SS_SS_REPLICATE_READ_REQ, // Secondary SS -> Primary SS

    // --- P2 Monster: EXEC Flow (NM-Orchestrated) ---
    OP_CLIENT_EXEC_REQ,       // Client -> NM: "EXEC file.txt"
    OP_NM_SS_INTERNAL_READ_REQ, // NM -> SS: "I (NM) need file.txt *now*"
    OP_SS_NM_INTERNAL_READ_RES, // SS -> NM: "Here is the content for file.txt"
    OP_NM_CLIENT_EXEC_OUTPUT, // NM -> Client: "Here is a line of output..." (Sent multiple times)
    OP_NM_CLIENT_EXEC_END,    // NM -> Client: "Execution finished."

    // --- Internal NM <-> SS Commands ---
    OP_NM_SS_CREATE_REQ,      // NM -> SS: "Please create this empty file"
    OP_SS_NM_CREATE_RES,      // SS -> NM: "OK, file created" or "Error"
    OP_SS_SYNC_FILE_INFO,     // SS -> NM: "FYI, I have this file..."

    // --- General & Error ---
    OP_HEARTBEAT_PING,        // NM <-> SS, NM <-> Client
    OP_HEARTBEAT_PONG,        // NM <-> SS, NM <-> Client
    OP_ERROR_RES,             // A generic, explicit error packet with a msg
    OP_DISCONNECT_REQ,
    OP_NM_SS_DELETE_REQ,
    OP_SS_NM_DELETE_RES,

    // request access

    OP_CLIENT_REQACCESS_REQ,    // <-- ADD THIS
    OP_NM_REQACCESS_RES,      // <-- ADD THIS
    OP_CLIENT_LISTREQS_REQ,   // <-- ADD THIS
    OP_NM_LISTREQS_RES,       // <-- ADD THIS
    OP_CLIENT_APPROVE_REQ,    // <-- ADD THIS (Covers approve/deny)
    OP_NM_APPROVE_RES        // <-- ADD THIS

} OpCode;

// --- Error Codes -----------------------------------------------------------
// Every response struct will have this. 0 is good.
typedef enum {
    ERR_NONE = 0,
    ERR_UNKNOWN,
    ERR_FILE_NOT_FOUND,
    ERR_FILE_EXISTS,
    ERR_USER_NOT_FOUND,
    ERR_DANGEROUS_COMMAND,
    ERR_ALREADY_ACTIVE,
    ERR_ACCESS_DENIED,        // P2: Your bread and butter
    ERR_SENTENCE_LOCKED,      // P1: Your bread and butter
    ERR_SENTENCE_OUT_OF_BOUNDS,
    ERR_WORD_OUT_OF_BOUNDS,
    ERR_INVALID_COMMAND,
    ERR_SS_DOWN,
    ERR_NM_DOWN,
    ERR_FILE_LOCKED,
    ERR_WRITE_FAILED,
    ERR_READ_FAILED,
    ERR_EXEC_FAILED,
    ERR_INVALID_PROTOCOL_VERSION,
    ERR_CHECKSUM_MISMATCH
} ErrorCode;

// --- Flags -----------------------------------------------------------------
// For VIEW command
#define VIEW_FLAG_A 0x01 // 0000 0001
#define VIEW_FLAG_L 0x02 // 0000 0010

// ACCESS flags
#define ACCESS_FLAG_READ_ADD  0x01
#define ACCESS_FLAG_WRITE_ADD 0x02
#define ACCESS_FLAG_REMOVE    0x04




// CRITICAL: ALL `send()` and `recv()` calls MUST use helper functions that
// enforce network byte order (htonl, ntohl, etc.) on ALL fields.
// Do not send this struct directly.
//
// CRITICAL (Implementation): When sending, enums MUST be cast to their
// explicit types (e.g., `htons((uint16_t)opcode)`) before network conversion.

#pragma pack(push, 1)
typedef struct {
    uint16_t version;    // Protocol version (e.g., PROTOCOL_VERSION)
    uint16_t opcode;     // The OpCode (cast from OpCode enum)
    uint32_t length;     // Total length of the *entire* packet (header + payload)
    uint32_t client_id;  // 0 until registered. Set by NM.
    uint32_t error;      // Cast from ErrorCode. 0 (ERR_NONE) on REQ.
    uint32_t checksum;   // CRC32/additive checksum of the *payload only*
    uint32_t reserved;   // For alignment and future use
} MsgHeader; // Total: 24 bytes
#pragma pack(pop)

static_assert(sizeof(MsgHeader) == 24, "MsgHeader must be 24 bytes");

// CLIENT_REGISTER_REQ
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} Payload_ClientRegisterReq;

// CLIENT_REGISTER_RES
typedef struct {
    uint32_t new_client_id;
} Payload_ClientRegisterRes;

// SS_REGISTER_REQ
typedef struct {
    uint32_t ss_id;       // 0 if new, non-zero if reconnecting
    uint8_t  is_reconnect; // 1 if reconnecting, 0 if fresh
    char ip[MAX_IP_LEN];
    uint16_t nm_port;
    uint16_t client_port;
    // On reconnect, NM will have to query SS for its file list.
    // For now, this is enough to tell NM *that* it reconnected.
} Payload_SSRegisterReq;

// CLIENT_VIEW_REQ
typedef struct {
    uint8_t flags; // VIEW_FLAG_A, VIEW_FLAG_L
} Payload_ClientViewReq;

// NM_VIEW_RES, NM_INFO_RES, NM_LIST_RES, NM_CLIENT_EXEC_OUTPUT
// All use a generic buffer payload. The *actual* bytes sent
// will be controlled by `header.length`.
typedef struct {
    char buffer[MAX_BUFFER_LEN];
} Payload_GenericBuffer;

// OP_ERROR_RES (explicit error payload)
typedef struct {
    char message[MAX_ERROR_MSG_LEN];
} Payload_Error;

// CLIENT_CREATE_REQ, CLIENT_DELETE_REQ, CLIENT_INFO_REQ,
// CLIENT_SS_READ_REQ, CLIENT_SS_STREAM_REQ, CLIENT_SS_UNDO_REQ,
// CLIENT_EXEC_REQ, NM_SS_INTERNAL_READ_REQ
typedef struct {
    char filename[MAX_FILENAME_LEN];
} Payload_FileRequest; // Generic for any op on a file

// NM_READ_RES, NM_STREAM_RES, NM_UNDO_RES, NM_WRITE_RES
typedef struct {
    char ss_ip[MAX_IP_LEN];
    uint16_t ss_port;
} Payload_SSRedirect; // "Go talk to this SS"

// SS_CLIENT_READ_RES, SS_NM_INTERNAL_READ_RES
typedef struct {
    uint32_t file_size;     // Total size (sent in *first* chunk)
    uint8_t  is_last_chunk; // 1 if this is the last chunk, 0 otherwise
    uint32_t data_len;      // How much data is *in this* chunk
    char     data[MAX_BUFFER_LEN]; // The chunk
} Payload_FileDataChunk;

// SS_CLIENT_STREAM_DATA
typedef struct {
    uint32_t sequence_no; // 0, 1, 2... to ensure ordering
    char     word[MAX_WRITE_CONTENT_LEN]; // Send one word at a time
} Payload_StreamData;

// CLIENT_ACCESS_REQ
typedef struct {
    char filename[MAX_FILENAME_LEN];
    char username[MAX_USERNAME_LEN];
    uint8_t flags; // ACCESS_FLAG...
} Payload_ClientAccessReq;

// CLIENT_WRITE_REQ
typedef struct {
    char filename[MAX_FILENAME_LEN];
    uint32_t sentence_index;
} Payload_ClientWriteReq;

// CLIENT_SS_WRITE_START
typedef struct {
    char filename[MAX_FILENAME_LEN];
    uint32_t sentence_index;
} Payload_ClientSSWriteStart;

// CLIENT_SS_WRITE_DATA
typedef struct {
    uint32_t word_index;
    char content[MAX_WRITE_CONTENT_LEN];
} Payload_ClientSSWriteData;

// CLIENT_CHECKPOINT_REQ, CLIENT_REVERT_REQ, CLIENT_VIEWCHECKPOINT_REQ
typedef struct {
    char filename[MAX_FILENAME_LEN];
    char tag[MAX_FILENAME_LEN]; // For the checkpoint tag
} Payload_CheckpointRequest;

typedef struct {
    char     filename[MAX_FILENAME_LEN];
    uint64_t new_file_size;
    // We'll add word/char counts here later. For now, size is enough.
} Payload_SSNMWriteComplete;

typedef struct {
    char     filename[MAX_FILENAME_LEN];
    uint64_t new_file_size;
} Payload_SSNMUndoComplete;

// --- REDO ---
typedef Payload_SSNMUndoComplete Payload_SSNMRedoComplete;

// --- CHECKPOINT ---
typedef Payload_SSNMUndoComplete Payload_SSNMRevertComplete;

// OP_NM_SS_REPLICATE_REQ
typedef struct {
    char filename[MAX_FILENAME_LEN];
    char primary_ss_ip[MAX_IP_LEN];
    uint16_t primary_ss_port;
} Payload_ReplicateRequest;

// OP_HEARTBEAT_PING, OP_HEARTBEAT_PONG
typedef struct {
    uint32_t sender_id; // The client_id or ss_id
    uint64_t timestamp_ms;
} Payload_Heartbeat;

typedef struct {
    char     filename[MAX_FILENAME_LEN];
    uint64_t file_size; 
    // We can add timestamps here later
} Payload_SSSyncFile;


// --- Generic "OK" or "Error" Responses ---
// OP_SS_REGISTER_RES, OP_NM_CREATE_RES, OP_NM_DELETE_RES, OP_NM_ACCESS_RES,
// OP_SS_CLIENT_WRITE_START_RES, OP_SS_CLIENT_ETIRW_RES,
// OP_SS_CLIENT_UNDO_RES, OP_SS_CLIENT_STREAM_END, OP_NM_CLIENT_EXEC_END
//
// All these ops just need a status. The `MsgHeader` already has the
// `error` field. So, for these, we send *only* the header
// with a length of `sizeof(MsgHeader)` and the `error` field set.
// No payload struct is needed.


// --- Payload Union ---------------------------------------------------------
// A single union to make reading/writing payloads easier
typedef union {
    Payload_ClientRegisterReq   client_reg_req;
    Payload_ClientRegisterRes   client_reg_res;
    Payload_SSRegisterReq       ss_reg_req;
    Payload_ClientViewReq       client_view_req;
    Payload_GenericBuffer       generic;
    Payload_Error               error;
    Payload_FileRequest         file_req;
    Payload_SSRedirect          redirect;
    Payload_FileDataChunk       file_chunk;
    Payload_StreamData          stream_data;
    Payload_ClientAccessReq     access_req;
    Payload_ClientWriteReq      write_req;
    Payload_ClientSSWriteStart  write_start;
    Payload_ClientSSWriteData   write_data;
    Payload_SSNMWriteComplete   write_complete;
    Payload_SSNMUndoComplete    undo_complete;
    Payload_SSNMRedoComplete    redo_complete;
    Payload_SSNMRevertComplete  revert_complete;
    Payload_CheckpointRequest   checkpoint_req;
    Payload_ReplicateRequest    replicate_req; 
    Payload_Heartbeat           heartbeat;
    Payload_SSSyncFile          ss_sync;
} MsgPayload;


// --- Protocol Helper Macros ------------------------------------------------
#define MSG_HEADER_SIZE sizeof(MsgHeader)
#define MSG_PAYLOAD_OFFSET (sizeof(MsgHeader))


#endif // PROTOCOL_H