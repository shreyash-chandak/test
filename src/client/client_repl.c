#include "common.h"
#include "protocol.h"
#include "utils.h"
#include "client_repl.h"
#include "parse_command.h"

void start_reply(int nm_socket){
    char line[1024];

    safe_printf("Welcome to Docs++. Type 'help' for commands.\n");

    while (1){
        
        printf("%s%s%s@%sdocs++> %s",BRIGHTBLUE, username, LIGHTRED, YELLOW, COLOR_RESET);
        fflush(stdout);

        // --- SIMPLE, BLOCKING FGETS ---
        if (fgets(line, sizeof(line), stdin) == NULL) {
            // User pressed Ctrl+D
            safe_printf("\nEnd of input detected. Exiting...\n");
            break;
        }

        // sanitize and handle command
        line[strcspn(line, "\n")] = '\0';

        ParsedCommand cmd = parse_command(line);

        // 2. Handle REPL-specific commands (help, exit, empty)
        switch (cmd.type) {
            case CMD_EXIT:
                safe_printf("Goodbye!\n");
                close(nm_socket);
                return; 

            case CMD_HELP:
                print_help_menu();
                continue;
            
            case CMD_EMPTY:
                continue;

            case CMD_CLEAR:
                system("clear || cls");
                continue;
                
            default:
                // 3. For all other commands, validate and send to server
                // This function will now be responsible for detecting
                // a disconnect and exiting.
                validate_and_send(&cmd, nm_socket);
        }
    }
    
    // Cleanup if loop breaks
    close(nm_socket);
}