#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <link.h>
#include "elf.h"
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>

#define PORT 3679
#define MAX_EVENTS 512
#define USE_FSTACK 1

int clientSocket;
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
void (*ff_run_ptr)(loop_func_t, void *);
int (*ff_epoll_create_ptr)(int);
int (*ff_epoll_ctl_ptr)(int, int, int, struct epoll_event *);
int (*ff_epoll_wait_ptr)(int, struct epoll_event *, int, int);
ssize_t (*ff_read_ptr)(int, void *, size_t);
ssize_t (*ff_write_ptr)(int, const void *, size_t);
int (*ff_fcntl_ptr)(int, int, ...);
int (*ff_ioctl_ptr)(int, unsigned long, ...);
int (*ff_getsockopt_ptr)(int, int, int, void *, socklen_t *);

int firstTime = 0;
int loop(void *arg) {

#if 0
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.fd = clientSocket;
	ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, clientSocket, &event);
#endif

	int nevents;
	int i;
	if (!firstTime) {
		nevents = ff_epoll_wait_ptr(epoll_fd,  events, MAX_EVENTS, 10000);

		if (nevents > 0) {
			printf("Number of events %d\n", nevents);
		}
	}

#if 0
	// I probably should copy this out to before loop is started, this is just to know if the connection was successful
	for (int i = 0; i < nevents; i++) {
		int err = -1;
		socklen_t len = sizeof(int);
		if (ff_getsockopt_ptr(events[i].data.fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0){
			ff_close_ptr(clientSocket);
			printf("getsockopt errno:%d %s\n", errno, strerror(errno));
			return -2;
		}
	}
#endif

	if (!firstTime) {
		for (int i = 0; i < nevents; i++) {
			if (events[i].events & EPOLLERR) {
				printf("We hit error EPOLLERR\n");
				ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
				ff_close_ptr(events[i].data.fd);
			}
			else if(events[i].events & EPOLLIN) {
				printf("Socket %d is ready to be read from\n", events[i].data.fd);
				char buf[256];
				size_t readlen = ff_read_ptr( events[i].data.fd, buf, sizeof(buf));
				printf("READ this: %s\n", buf);
			} else if (events[i].events & EPOLLOUT) {
				firstTime = 1;
				printf("Socket %d is ready to be written to\n", events[i].data.fd);
				printf("Client: \t");
				char buf[256];
				scanf("%s", &buf[0]);
				ff_write_ptr(events[i].data.fd, buf, strlen(buf));

#if 0
				event.events = EPOLLIN | EPOLLOUT;
				event.data.fd = clientSocket;
				ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, clientSocket, &event);
#endif
			}
			printf("Event content: %u\n", (unsigned)events[i].events);
		}
	} else {
				printf("Client: \t");
				char buf[256];
				scanf("%s", &buf[0]);
				ff_write_ptr(events[i].data.fd, buf, strlen(buf));
	}
	//printf("All done, nevents %d\n", nevents);

}

// In f-stack mode, run like:
// ./client --conf /data/f-stack/config.ini --proc-type=primary --proc-id=0
int main(int argc, char * const argv[]) {

	int ret;
	struct sockaddr_in serverAddr;
	char buffer[1024];

	void *handle;
	handle = dlopen("libfstack.so", RTLD_NOW);
	fprintf(stderr, "dlopen is called\n");
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
    		ff_run_ptr = (void (*)(loop_func_t, void *))dlsym(handle, "ff_run");
		ff_epoll_create_ptr = (int (*)(int))dlsym(handle, "ff_epoll_create");
		ff_epoll_ctl_ptr = (int (*)(int, int, int, struct epoll_event *))dlsym(handle, "ff_epoll_ctl");
		ff_epoll_wait_ptr = (int (*)(int, struct epoll_event *, int, int))dlsym(handle, "ff_epoll_wait");
		ff_read_ptr = (ssize_t (*)(int, void *, size_t))dlsym(handle, "ff_read");
		ff_write_ptr = (ssize_t (*)(int, const void *, size_t))dlsym(handle, "ff_write");
		ff_fcntl_ptr = (int (*)(int, int, ...))dlsym(handle, "ff_fcntl");
		ff_ioctl_ptr = (int (*)(int, unsigned long, ...))dlsym(handle, "ff_ioctl");
		ff_getsockopt_ptr = (int (*)(int, int, int, void *, socklen_t *))dlsym(handle, "ff_getsockopt");

		if (	!ff_socket_ptr ||
			!ff_send_ptr ||
			!ff_recv_ptr ||
			!ff_connect_ptr ||
			!ff_close_ptr ||
			!ff_getsockname_ptr ||
			!ff_bind_ptr ||
			!ff_run_ptr ||
			!ff_epoll_create_ptr ||
			!ff_epoll_ctl_ptr ||
			!ff_epoll_wait_ptr ||
			!ff_listen_ptr ||
			!ff_read_ptr ||
			!ff_write_ptr ||
			!ff_fcntl_ptr ||
			!ff_getsockopt_ptr ||
			!ff_ioctl_ptr ||
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
	} else {
		fprintf(stderr, "Using the Linux Kernel based version\n");
    		ff_socket_ptr = &socket;
    		ff_send_ptr = &send;
    		ff_recv_ptr = &recv;
    		ff_connect_ptr = &connect;
    		ff_close_ptr = &close;
	}

	//clientSocket = ff_socket_ptr(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	clientSocket = ff_socket_ptr(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(clientSocket < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Client Socket is created.\n");

	int on = 1;
	//ret = ff_fcntl_ptr(clientSocket, FIONBIO, &on);
	ret = ff_ioctl_ptr(clientSocket, FIONBIO, &on);
	if (ret < 0) {
		printf("[-] error in fcntl. errno: %d, %s\n", errno, strerror(errno));
		return 0;
	}


	//memset(&serverAddr, '\0', sizeof(serverAddr));
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("10.250.136.19");
	//serverAddr.sin_addr.s_addr = inet_addr("10.250.136.21");
	
	/*---Connect to server---*/
	if (ff_connect_ptr(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0 ) {
		if(errno != EINPROGRESS) {
			printf("[-]Error in connection. (errno: %d, %s)\n", errno, strerror(errno));
			exit(errno);
		}
		printf("ff_connect returns errno: %d, %s\n", errno, strerror(errno));
	}


#if 0
	/*---Add socket to epoll---*/
	epoll_fd = ff_epoll_create_ptr(1);
	event.events = EPOLLIN | EPOLLOUT;
	event.data.fd = clientSocket;
	ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, clientSocket, &event);
#endif

	int err = -1;
	socklen_t len = sizeof(int);
	ret = ff_getsockopt_ptr(clientSocket, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret < 0){
		ff_close_ptr(clientSocket);
		printf("getsockopt errno:%d %s\n", errno, strerror(errno));
		return -2;
	}
	printf("ff_getsockopt_ptr's return value: %d\n", ret);

#if 1
	/*---Add socket to epoll---*/
	epoll_fd = ff_epoll_create_ptr(1);
	event.events = EPOLLIN | EPOLLOUT;
	event.data.fd = clientSocket;
	ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, clientSocket, &event);
#endif

	events = calloc (MAX_EVENTS, sizeof event);
	ff_run_ptr(loop, NULL);


#if 0
	//ret = ff_connect_ptr(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	char myIP[16];
	inet_ntop(AF_INET, &serverAddr.sin_addr, myIP, sizeof(myIP));
	int myPort = ntohs(serverAddr.sin_port);
	printf("Attempting connect to port %d on IP %s\n", myPort, myIP);
	ret = ff_connect_ptr(clientSocket, (struct linux_sockaddr *)&serverAddr, sizeof(serverAddr));
#if 1
	if(ret < 0){
		printf("[-]Error in connection. error code: %d (errno: %d, %s)\n", ret, errno, strerror(errno));
		exit(1);
	}
#endif
	printf("[+]Connected to Server.\n");

	while(1){
		printf("Client: \t");
		scanf("%s", &buffer[0]);
		ff_send_ptr(clientSocket, buffer, strlen(buffer), 0);

		if(strcmp(buffer, ":exit") == 0){
			ff_close_ptr(clientSocket);
			printf("[-]Disconnected from server.\n");
			exit(1);
		}

		if(ff_recv_ptr(clientSocket, buffer, 1024, 0) < 0){
			printf("[-]Error in receiving data.\n");
		}else{
			printf("Server: \t%s\n", buffer);
		}
	}
#endif

	return 0;
}
