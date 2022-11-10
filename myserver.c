#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <link.h>
#include "elf.h"
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"
#include <errno.h>
#include <assert.h>

#define PORT 3678
#define MAX_EVENTS 512

/* kevent set */
struct kevent kevSet;
/* events */
//struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;
int epoll_fd;
struct epoll_event event;
struct epoll_event *events;

int (*ff_init_ptr)(int, char * const);
int (*ff_socket_ptr)(int, int, int);
ssize_t (*ff_send_ptr)(int, const void*, size_t, int);
ssize_t (*ff_recv_ptr)(int, void*, size_t, int);
int (*ff_accept_ptr)(int, struct linux_sockaddr *, socklen_t *);
int (*ff_connect_ptr)(int, const struct sockaddr *, socklen_t);
int (*ff_bind_ptr)(int, const struct linux_sockaddr *a, socklen_t);
int (*ff_close_ptr)(int);
int (*ff_listen_ptr)(int, int);
int (*ff_getsockname_ptr)(int, struct linux_sockaddr *, socklen_t *);
int (*ff_kevent_ptr)(int, const struct kevent *, int, struct kevent *, int, const struct timespec *);
void (*ff_run_ptr)(loop_func_t, void *);
int (*ff_kqueue_ptr)(void);
int (*ff_epoll_create_ptr)(int);
int (*ff_epoll_ctl_ptr)(int, int, int, struct epoll_event *);
int (*ff_epoll_wait_ptr)(int, struct epoll_event *, int, int);
ssize_t (*ff_read_ptr)(int, void *, size_t);
ssize_t (*ff_write_ptr)(int, const void *, size_t);
int (*ff_setsockopt_ptr)(int, int, int, const void*, socklen_t);


int loop(void *arg) {
    /* Wait for events to happen */

	int nevents;
	do {
		int nevents = ff_epoll_wait_ptr(epoll_fd,  events, MAX_EVENTS, 100);
	} while (nevents <= 0);
    int i;
    if (nevents > 0) {
	    printf("Number of events %d\n", nevents);
    }

    for (i = 0; i < nevents; ++i) {
        /* Handle new connect */
        if (events[i].data.fd == sockfd) {
	    printf("was equal sockfd\n");
#if 1
            while (1) {
                int nclientfd = ff_accept_ptr(sockfd, NULL, NULL);
                if (nclientfd < 0) {
                    break;
                }

                /* Add to event list */
                event.data.fd = nclientfd;
                event.events  = EPOLLIN;
                if (ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, nclientfd, &event) != 0) {
                    printf("ff_epoll_ctl failed:%d, %s\n", errno,
                        strerror(errno));
                    break;
                }
            }
#endif
        } else {
	    //printf("was not equal sockfd\n");
#if 1
            if (events[i].events & EPOLLERR ) {
                /* Simply close socket */
                ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                ff_close_ptr(events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                char buf[256];
                size_t readlen = ff_read_ptr( events[i].data.fd, buf, sizeof(buf));
		printf("READ this: %s\n", buf);
                if(readlen > 0) {
                    ff_write_ptr(events[i].data.fd, buf, readlen);
                } else {
                    ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ff_close_ptr(events[i].data.fd);
                }
            } else {
                printf("unknown event: %8.8X\n", events[i].events);
            }
#endif
        }
    }
    return 0;
}

// In f-stack mode, run like:
// ./client --conf /data/f-stack/config.ini --proc-type=primary --proc-id=0
int main(int argc, char * const argv[]) {

	int ret;
	struct sockaddr_in serverAddr;

	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;

	char buffer[1024];
	pid_t childpid;

	void *handle;
	handle = dlopen("libfstack.so", RTLD_NOW);
	if (!handle) {
		fprintf(stderr, "Error(dlopen): %s\n", dlerror());
	}
	fprintf(stderr, "dlopen is called, handle is %llu\n", (long long unsigned)handle);
	fflush(stderr);
	int use_fstack = (handle != NULL);

	if (use_fstack) {
		fprintf(stderr, "Using the f-stack based version\n");
		ff_init_ptr = (int (*)(int, char * const))dlsym(handle, "ff_init");
		if (!ff_init_ptr) {
			fprintf(stderr, "Error(ff_init): %s\n", dlerror());
			dlclose(handle);
			return EXIT_FAILURE;
		}
    		ff_socket_ptr = (int (*)(int, int, int))dlsym(handle, "ff_socket");
    		ff_send_ptr = (ssize_t (*)(int, const void*, size_t, int))dlsym(handle, "ff_send");
    		ff_recv_ptr = (ssize_t (*)(int, void*, size_t, int))dlsym(handle, "ff_recv");
    		ff_connect_ptr = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(handle, "ff_connect");
    		ff_close_ptr = (int (*)(int))dlsym(handle, "ff_close");
    		ff_bind_ptr = (int (*)(int, const struct linux_sockaddr *a, socklen_t))dlsym(handle, "ff_bind");
    		ff_accept_ptr = (int (*)(int, struct linux_sockaddr *, socklen_t *))dlsym(handle, "ff_accept");
    		ff_listen_ptr = (int (*)(int, int))dlsym(handle, "ff_listen");
    		ff_getsockname_ptr = (int (*)(int, struct linux_sockaddr *, socklen_t *))dlsym(handle, "ff_getsockname");
    		ff_kevent_ptr = (int (*)(int, const struct kevent *, int, struct kevent *, int, const struct timespec *))dlsym(handle, "ff_kevent");
    		ff_kqueue_ptr = (int (*)(void))dlsym(handle, "ff_kqueue");
    		ff_run_ptr = (void (*)(loop_func_t, void *))dlsym(handle, "ff_run");
		ff_epoll_create_ptr = (int (*)(int))dlsym(handle, "ff_epoll_create");
		ff_epoll_ctl_ptr = (int (*)(int, int, int, struct epoll_event *))dlsym(handle, "ff_epoll_ctl");
		ff_epoll_wait_ptr = (int (*)(int, struct epoll_event *, int, int))dlsym(handle, "ff_epoll_wait");
		ff_read_ptr = (ssize_t (*)(int, void *, size_t))dlsym(handle, "ff_read");
		ff_write_ptr = (ssize_t (*)(int, const void *, size_t))dlsym(handle, "ff_write");

		if (	!ff_socket_ptr ||
			!ff_send_ptr ||
			!ff_recv_ptr ||
			!ff_connect_ptr ||
			!ff_close_ptr ||
			!ff_getsockname_ptr ||
			!ff_bind_ptr ||
			!ff_kevent_ptr ||
			!ff_run_ptr ||
			!ff_epoll_create_ptr ||
			!ff_epoll_ctl_ptr ||
			!ff_epoll_wait_ptr ||
			!ff_kqueue_ptr ||
			!ff_listen_ptr ||
			!ff_read_ptr ||
			!ff_write_ptr ||
			!ff_accept_ptr) {
			fprintf(stderr, "Error(rest): %s\n", dlerror());
			dlclose(handle);
			return EXIT_FAILURE;
		}
		const int myargc = 4;
		char *myargv[4];
		myargv[0] = argv[0];
		myargv[1] = "--conf=/data/f-stack/config.ini";
		myargv[2] = "--proc-type=primary";
		myargv[3] = "--proc-id=0";
		ff_init_ptr(myargc, (char * const)myargv);
		assert((kq = ff_kqueue_ptr()) > 0);
	} else {
		fprintf(stderr, "Using the Linux Kernel based version\n");
    		ff_socket_ptr = &socket;
    		ff_send_ptr = &send;
    		ff_recv_ptr = &recv;
    		ff_connect_ptr = &connect;
    		ff_close_ptr = &close;
    		ff_bind_ptr = &bind;
    		ff_listen_ptr = &listen;
    		ff_accept_ptr = &accept;
    		ff_getsockname_ptr = &getsockname;
		ff_epoll_create_ptr = &epoll_create;
		ff_epoll_ctl_ptr = &epoll_ctl;
		ff_epoll_wait_ptr = &epoll_wait;
		ff_read_ptr = &read;
		ff_write_ptr = &write;
		ff_setsockopt_ptr = &setsockopt;
	}


	sockfd = ff_socket_ptr(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Server Socket is created.\n");

    	bzero(&serverAddr, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	// s12's Linux Kernel
	serverAddr.sin_addr.s_addr = inet_addr("10.250.136.19");
	// s13's DPDK
	//serverAddr.sin_addr.s_addr = inet_addr("10.250.136.21");
	// s13's Linux Kernel
	//serverAddr.sin_addr.s_addr = inet_addr("10.250.136.99");

	int nodelay = 1;
        ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const void*)&nodelay, sizeof(int));
        if (ret) {
                ff_close_ptr(sockfd);
                printf("setsockopt errno:%d %s\n", errno, strerror(errno));
                return -3;
        }
        printf("ff_setsockopt_ptr's return value: %d\n", ret);

	ret = ff_bind_ptr(sockfd, (struct linux_sockaddr *)&serverAddr, sizeof(serverAddr));
	if(ret < 0){
		printf("[-]Error in binding.\n");
		exit(1);
	}

	char myIP[16];
	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	socklen_t len = sizeof(my_addr);
	ff_getsockname_ptr(sockfd, (struct sockaddr *)&my_addr, &len);
	inet_ntop(AF_INET, &my_addr.sin_addr, myIP, sizeof(myIP));
	int myPort = ntohs(my_addr.sin_port);
	printf("[+]Bind to port %d on IP %s\n", myPort, myIP);

	if(ff_listen_ptr(sockfd, 512) == 0){
		printf("[+]Listening....\n");
	}else{
		printf("[-]Error in binding.\n");
	}

#if 0
	int nclientfd = ff_accept_ptr(sockfd, NULL, NULL);
	if (nclientfd < 0) {
		printf("[-]Error in accept.\n");
	}
	printf("Accept is done\n");
#endif

#if 0
	EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
	/* Update kqueue */
	ff_kevent_ptr(kq, &kevSet, 1, NULL, 0, NULL);
	printf("-------------------- Reza - Calling loop\n");
	fflush(stdout);
	ff_run_ptr(loop, NULL);
#endif

	while (1) {
		newSocket = ff_accept_ptr(sockfd, (struct sockaddr*)&newAddr, &addr_size);
		if(newSocket < 0){
			exit(1);
		}
		printf("Connection accepted from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
		int nodelay = 1;
        	ret = setsockopt(newSocket, IPPROTO_TCP, TCP_NODELAY, (const void*)&nodelay, sizeof(int));
        	if (ret) {
                	ff_close_ptr(newSocket);
                	printf("setsockopt errno:%d %s\n", errno, strerror(errno));
        	        break;
        	}
        	printf("ff_setsockopt_ptr's return value: %d\n", ret);

#if 0
		if((childpid = fork()) == 0){
			close(sockfd);
#endif

			while(1){
				printf("Waiting for client to send somethin\n");
				recv(newSocket, buffer, 1024, 0);
				if (strcmp(buffer, ":exit") == 0){
					printf("Disconnected from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
					break;
				} else {
					printf("Client: %s\n", buffer);
					send(newSocket, buffer, strlen(buffer), 0);
					bzero(buffer, sizeof(buffer));
				}
			}
#if 0
		}
#endif

	}

#if 0
	epoll_fd = ff_epoll_create_ptr(1);
	if (epoll_fd < 0) {
		printf("epoll_create failed\n");
		return 1;
	}
	event.data.fd = sockfd;
	event.events = EPOLLIN;
	int s = ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, sockfd, &event);
	if (s == -1) {
		printf("epoll_ctl failed\n");
		return 1;
	}

	/* Buffer where events are returned */
	events = calloc (MAX_EVENTS, sizeof event);

	loop(NULL);
	//ff_run_ptr(loop, NULL);
#endif

	return 0;
}
