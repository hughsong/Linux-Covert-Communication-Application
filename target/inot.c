#include <stdio.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <pthread.h>
#include "config.h"
#include "raw_socket.h"

#pragma pack(1)

#define TRUE 1
#define FALSE 0
#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUF_LEN	(1024 * (EVENT_SIZE + 16))
#define ALL_MASK 0xffffffff

// Globals - volatile qualifier tells compiler that variable can be modified asynchronously during program execution
static volatile sig_atomic_t doneflag = FALSE;


//----------- Function Prototypes --------------------
static void set_done_flag (int);
void print_mask(int);

int inot (char* dir, char* file) {
	int len, i, ret, fd, wd;
	struct timeval time;
	static struct inotify_event *event;
	fd_set rfds;
	char buf[BUF_LEN];
	struct sigaction act;
    char directory[STR_SIZE];
    memset(directory, 0, strlen(directory));
    strcpy(directory, dir);
    char filename[STR_SIZE];
    memset(filename, 0, strlen(filename));
    strcpy(filename, file);
    char full_path[MAX_SIZE];
    pthread_t thread;

	// time out after 30 seconds	
	time.tv_sec = 30;
	time.tv_usec = 0;

	fd = inotify_init();
	if (fd < 0)
		perror ("inotify_init");

	wd = inotify_add_watch (fd, directory, (uint32_t)IN_CREATE|IN_CLOSE);
	
	if (wd < 0) {
		perror ("inotify_add_watch");
        return 0;
    }

	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);

	// set up the signal handler 
	act.sa_handler = set_done_flag;
	act.sa_flags = 0;
	if ((sigemptyset (&act.sa_mask) == -1 || sigaction (SIGINT, &act, NULL) == -1)) {
		perror ("Failed to set SIGINT handler");
		exit (EXIT_FAILURE);
	}

	while (!doneflag) {
		ret = select (fd + 1, &rfds, NULL, NULL, NULL);
		len = read (fd, buf, BUF_LEN);
	
		i = 0;
		if (len < 0)  {
            if (errno == EINTR) /* need to reissue system call */
                perror ("read");
            else
                perror ("read");
		} else if (!len) {/* BUF_LEN too small? */
			printf ("buffer too small!\n");
			return 0;
		}

		while (i < len) {
            event = (struct inotify_event *) &buf[i];
            i += EVENT_SIZE + event->len;
		}
	
		if (ret < 0)
			perror ("select");
		else if (!ret)
			printf ("timed out\n");
		else if (FD_ISSET (fd, &rfds)) {
            if ((event->mask & IN_CLOSE) && !(event->mask & IN_ISDIR) && (strcmp((event->name), filename) == 0)) {
                memset(full_path, 0, MAX_SIZE);
                strncat(full_path, directory, MAX_SIZE - strlen(full_path));
                strncat(full_path, "/", MAX_SIZE - strlen(full_path));
                strncat(full_path, filename, MAX_SIZE - strlen(full_path));
                printf("\n[+]Detected file creation: %s\n", full_path);
                if (pthread_create(&thread, NULL, Thread_send, (void*)full_path)) {
                    printf("[-]ERROR: Fail to create thread!\n");
                }
                // Join the thread
                pthread_join(thread, NULL);
                printf ("\n[+]Cleaning up and terminating inotify...\n");
                fflush (stdout);
                ret = inotify_rm_watch (fd, wd);
                if (ret)
                    perror ("inotify_rm_watch");
                if (close(fd))
                    perror ("close");
                return 0;
            }
		}
	}
	
	printf ("[+]Cleaning up and Terminating....................\n");
	fflush (stdout);
	ret = inotify_rm_watch (fd, wd);
	if (ret)
		perror ("inotify_rm_watch");
	if (close(fd))
		perror ("close");
	return 0;
}

static void set_done_flag (int signo) {
	doneflag = TRUE;
}
