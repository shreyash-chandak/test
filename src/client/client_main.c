#include "common.h"
#include "protocol.h"
#include "utils.h"
#include "client_repl.h"
#include <termios.h> // For turning off terminal echo

static void get_password(char* buffer, size_t size) {
    struct termios old_term, new_term;
    
    safe_printf("Password: (invisible on terminal)");
    
    // Turn off echoing
    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        perror("tcgetattr");
    }
    new_term = old_term;
    new_term.c_lflag &= ~ECHO; // Unset the ECHO flag
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
        perror("tcsetattr");
    }
    
    
    // Read the password
    if (fgets(buffer, size, stdin) == NULL) {
        buffer[0] = '\0';
    }
    
    // Restore terminal settings
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    safe_printf("\n"); // Add the newline that was suppressed
    
    buffer[strcspn(buffer, "\r\n")] = 0; // Remove newline
}

int main(int argc, char const *argv[]){
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <nm_ip> <nm_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* nm_ip = argv[1];
    uint16_t nm_port = (uint16_t)atoi(argv[2]);

    int nm_socket_fd;
    struct sockaddr_in nm_addr;
    
    init_printf_mutex(); // For safe_printf

    // Connect to Name Server
    if ((nm_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket"); exit(EXIT_FAILURE);
    }
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_port = htons(nm_port);
    if(inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr) <= 0) {
        perror("inet_pton"); exit(EXIT_FAILURE);
    }
    if (connect(nm_socket_fd, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0) {
        perror("connect"); exit(EXIT_FAILURE);
    }

    safe_printf("Connected to Name Server at %s:%d\n", nm_ip, nm_port);

    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    
    safe_printf("Username: ");
    if (fgets(username, sizeof(username), stdin) == NULL) {
        perror("fgets username failed");
    }
    username[strcspn(username, "\r\n")] = 0;

    get_password(password, sizeof(password));


    // --- Send Registration ---
    MsgHeader header;
    MsgPayload payload;
    memset(&header, 0, sizeof(header));
    memset(&payload, 0, sizeof(payload));

    header.version = PROTOCOL_VERSION;
    header.opcode = OP_CLIENT_REGISTER_REQ;
    header.length = sizeof(MsgHeader) + sizeof(Payload_ClientRegisterReq);
    
    strncpy(payload.client_reg_req.username, username, MAX_USERNAME_LEN - 1);
    strncpy(payload.client_reg_req.password, password, MAX_PASSWORD_LEN - 1);
    // Force null termination
    payload.client_reg_req.username[MAX_USERNAME_LEN - 1] = '\0';
    payload.client_reg_req.password[MAX_PASSWORD_LEN - 1] = '\0';

    if (send_message(nm_socket_fd, &header, &payload) == -1) {
        safe_printf("Failed to send registration\n");
        close(nm_socket_fd);
        exit(EXIT_FAILURE);
    }

    // --- Wait for Registration Response ---
    if (recv_message(nm_socket_fd, &header, &payload) <= 0) {
        safe_printf("Server disconnected during registration\n");
        close(nm_socket_fd);
        exit(EXIT_FAILURE);
    }

    if (header.opcode != OP_CLIENT_REGISTER_RES || header.error != ERR_NONE) {
        safe_printf("Failed to register.\nServer error: %s\n", payload.error.message);
        close(nm_socket_fd);
        exit(EXIT_FAILURE);
    }
    
    uint32_t my_client_id = payload.client_reg_res.new_client_id;
    safe_printf("Successfully registered as Client %u\n", my_client_id);
    
    // this blocks and runs the main loop
    start_reply(nm_socket_fd);

    // Cleanup
    safe_printf("Disconnecting...\n");
    close(nm_socket_fd);
    destroy_printf_mutex();
    return 0;
}