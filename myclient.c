#include <stdio.h>
#include <netinet/tcp.h>
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
#include <rte_pdump.h>
#include <signal.h>

#define PORT 3678
#define MAX_EVENTS 512
#define USE_FSTACK 1

int clientSocket;
struct sockaddr_in serverAddr;
int epoll_fd;
struct epoll_event event;
struct epoll_event *events;
int ret;

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
int (*ff_setsockopt_ptr)(int, int, int, const void*, socklen_t);


static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		fprintf(stderr, "\nSignal %d received, preparing to exit...\n",
			signum);
		/* uninitialize packet capture framework */
		rte_pdump_uninit();
		signal(signum, SIG_DFL);
		kill(getpid(), signum);
	}
}

unsigned getTimeMs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
}

uint64_t getTimeUs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000000ULL + (tv.tv_usec);
}

void busyLoop(unsigned delayMs) {
    	unsigned startMs = getTimeMs();
	while (1) {
		unsigned endMs = getTimeMs();
		if ((endMs - startMs) >= delayMs) {
			break;
		}
	}
}


int count = 0;
int prioritizeRecv = 0;
uint64_t startTime = 0;
int loop(void *arg) {
	int nevents;
	int i;
	nevents = ff_epoll_wait_ptr(epoll_fd,  events, MAX_EVENTS, 10000);
	//printf("Number of events %d\n", nevents);

	for (int i = 0; i < nevents; i++) {
		assert(events[i].data.fd == clientSocket);
		if (events[i].events & EPOLLERR) {
			printf("We hit error EPOLLERR\n");
			ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
			ff_close_ptr(events[i].data.fd);
		}
		else if(events[i].events & EPOLLIN) {
			printf("Socket %d is ready to be read from\n", events[i].data.fd);
			char buf[256];
			size_t readlen = ff_read_ptr(events[i].data.fd, buf, sizeof(buf));
			uint64_t endTime = getTimeUs();
			printf("+++++++++++++++++ READ this: %s (took %lu us for the round trip)\n", buf, (endTime - startTime));
			prioritizeRecv = 0;
		} else if (events[i].events & EPOLLOUT && !prioritizeRecv) {
			printf("Socket %d is ready to be written to\n", events[i].data.fd);
			printf("Client: \t");
			const int bufsize = 512;
			char buf[bufsize];
			buf[bufsize - 1] = '\0';
                        memset(buf, '\0', bufsize);
			sprintf(buf, "%d", count);
			busyLoop(200);
			//unsigned written_len = ff_write_ptr(events[i].data.fd, buf, strlen(buf));
			unsigned written_len = ff_send_ptr(events[i].data.fd, buf, strlen(buf), 0);
			startTime = getTimeUs();
			printf("Wrote %u bytes [counter: %d]\n", written_len, count);
			count++;
			prioritizeRecv = 1;

		}
		//printf("Event content: %u\n", (unsigned)events[i].events);
	}

}

// In f-stack mode, run like:
// ./client --conf /data/f-stack/config.ini --proc-type=primary --proc-id=0
int main(int argc, char * const argv[]) {

	char buffer[1024];

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

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
		ff_setsockopt_ptr = (int (*)(int, int, int, const void*, socklen_t))dlsym(handle, "ff_setsockopt");

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
			!ff_setsockopt_ptr ||
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
		ff_setsockopt_ptr = &setsockopt;
	}

	clientSocket = ff_socket_ptr(AF_INET, SOCK_STREAM, 0);
	if(clientSocket < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Client Socket is created.\n");

	printf("Initializing pdump lib..\n");
	rte_pdump_init();

	int on = 1;
	ret = ff_ioctl_ptr(clientSocket, FIONBIO, &on);
	if (ret < 0) {
		printf("[-] error in fcntl. errno: %d, %s\n", errno, strerror(errno));
		return 0;
	}

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("10.250.136.19");
	
	/*---Connect to server---*/
	if (ff_connect_ptr(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0 ) {
		if(errno != EINPROGRESS) {
			printf("[-]Error in connection. (errno: %d, %s)\n", errno, strerror(errno));
			exit(errno);
		}
		printf("ff_connect returns errno: %d, %s\n", errno, strerror(errno));
	}

	int err = -1;
	socklen_t len = sizeof(int);
	ret = ff_getsockopt_ptr(clientSocket, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret < 0){
		ff_close_ptr(clientSocket);
		printf("getsockopt errno:%d %s\n", errno, strerror(errno));
		return -2;
	}
	printf("ff_getsockopt_ptr's return value: %d\n", ret);
        
	int nodelay = 1;
        ret = ff_setsockopt_ptr(clientSocket, IPPROTO_TCP, TCP_NODELAY, (const void*)&nodelay, len);
        if (ret) {
		ff_close_ptr(clientSocket);
                printf("setsockopt errno:%d %s\n", errno, strerror(errno));
                return -3;
	}
	printf("ff_setsockopt_ptr's return value: %d\n", ret);

	/*---Add socket to epoll---*/
	epoll_fd = ff_epoll_create_ptr(1);
	event.events = EPOLLIN | EPOLLOUT;
	//event.events = EPOLLOUT;
	event.data.fd = clientSocket;
	ff_epoll_ctl_ptr(epoll_fd, EPOLL_CTL_ADD, clientSocket, &event);

	events = calloc (MAX_EVENTS, sizeof event);
	ff_run_ptr(loop, NULL);


#if 0
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

