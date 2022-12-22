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

#define MAX_EVENTS 512
#define USE_FSTACK 1

int serverPort = 8000;

int clientSocket;
struct sockaddr_in serverAddr;
int epfd;
struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];
int ret;
int use_fstack;
int id;

unsigned connStart, connEnd;

int (*ff_init_ptr)(int, char * const);
int (*ff_socket_ptr)(int, int, int);
ssize_t (*ff_send_ptr)(int, const void*, size_t, int);
ssize_t (*ff_recv_ptr)(int, void*, size_t, int);
int (*ff_accept_ptr)(int, struct sockaddr *, socklen_t *);
int (*ff_connect_ptr)(int, const struct sockaddr *, socklen_t);
int (*ff_bind_ptr)(int, const struct sockaddr *a, socklen_t);
int (*ff_close_ptr)(int);
int (*ff_listen_ptr)(int, int);
int (*ff_getsockname_ptr)(int, struct sockaddr *, socklen_t *);
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
int (*ff_select_ptr)(int, fd_set *, fd_set *, fd_set *, struct timeval *);

void linux_stack_loop(loop_func_t myloop, void* args) {
	while (1) {
		myloop(args);
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		fprintf(stderr, "\nSignal %d received, preparing to exit...\n",
			signum);
		/* uninitialize packet capture framework */
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
int prevnEvent = -1;
int firstTime = 1;
int secondTime = 0;
int loop(void *arg) {
	if (firstTime) {
		firstTime = 0;

		clientSocket = ff_socket_ptr(AF_INET, SOCK_STREAM, 0);
		printf("clientSocket:%d\n", clientSocket);
		if (clientSocket < 0) {
			printf("ff_socket failed\n");
			exit(1);
		}

		int on = 1;
		ff_ioctl_ptr(clientSocket, FIONBIO, &on);

		bzero(&serverAddr, sizeof(serverAddr));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(serverPort);
		inet_pton(AF_INET, "10.254.153.112", &(serverAddr.sin_addr)); // vp23

		int err = -1;
		socklen_t len = sizeof(int);
		int nodelay = 1;
		ret = ff_setsockopt_ptr(clientSocket, IPPROTO_TCP, TCP_NODELAY, (const void*)&nodelay, len);
		if (ret) {
			ff_close_ptr(clientSocket);
			printf("setsockopt errno:%d %s\n", errno, strerror(errno));
			return -3;
		}
		printf("ff_setsockopt_ptr's return value: %d\n", ret);

		errno = 0;
		printf("Connecting...\n");
		ret = ff_connect_ptr(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
		if(ret != 0 && errno != EINPROGRESS) {
			printf("[-] Connection failed, errno: %d (%s)\n", errno, strerror(errno));
			exit(errno);
		}
		printf("[+] Connection is done, errno: %d (%s)\n", errno, strerror(errno));
		connStart = getTimeUs();

		assert((epfd = ff_epoll_create_ptr(10)) > 0);
		ev.data.fd = clientSocket;
		ev.events = EPOLLIN | EPOLLOUT;
		ff_epoll_ctl_ptr(epfd, EPOLL_CTL_ADD, clientSocket, &ev);
		printf("Created the epoll fd\n");
		secondTime = 1;
		return 0;
	}
	if (secondTime) {
		int nevents = ff_epoll_wait_ptr(epfd,  events, MAX_EVENTS, 10000);
		for (int i = 0; i < nevents; i++) {
			if (events[i].data.fd == clientSocket && events[i].events & EPOLLOUT) {
				connEnd = getTimeUs();
				printf("Finally connected (took %u us)\n", connEnd - connStart);
				secondTime = 0;
			}
		}
		return 0;
	}

	int nevents;
	int i;
	socklen_t len = sizeof(int);
	nevents = ff_epoll_wait_ptr(epfd,  events, MAX_EVENTS, 10000);
	if (nevents != prevnEvent) {
		printf("Number of events %d\n", nevents);
		prevnEvent = nevents;
	}

	for (int i = 0; i < nevents; i++) {
		assert(events[i].data.fd == clientSocket);

		if (events[i].events & EPOLLERR) {
			printf("We hit error EPOLLERR\n");
			ff_epoll_ctl_ptr(epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
			ff_close_ptr(events[i].data.fd);
		}
		else if(events[i].events & EPOLLIN) {
			//printf("Socket %d is ready to be read from\n", events[i].data.fd);
			const int bufsize = 512;
			char buf[bufsize];
                        memset(buf, '\0', bufsize);
			size_t readlen = ff_read_ptr(events[i].data.fd, buf, bufsize);
			uint64_t endTime = getTimeUs();
			printf("READ this: %s (took %lu us for the round trip)\n", buf, (endTime - startTime));
			prioritizeRecv = 0;
		} else if (events[i].events & EPOLLOUT && !prioritizeRecv) {
		//} else if (events[i].events & EPOLLOUT) {
			printf("Socket %d is ready to be written to\n", events[i].data.fd);
			//printf("Client: \t");
			const int bufsize = 512;
			char buf[bufsize];
                        memset(buf, '\0', bufsize);
			sprintf(buf, "Client %d: %d", id, count);
			busyLoop(200);
			unsigned written_len = ff_send_ptr(events[i].data.fd, buf, strlen(buf), 0);
			startTime = getTimeUs();
			printf("Wrote %u bytes [counter: %d]\n", written_len, count);
			count++;
			prioritizeRecv = 1;

		}
		//printf("Event content: %u\n", (unsigned)events[i].events);
	}

	return 0;
}

// In f-stack mode, run like:
// ./client [ID]
int main(int argc, char * const argv[]) {

	id = argc > 1 ? atoi(argv[1]) : 0;

	char buffer[1024];

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	void *handle;
	handle = dlopen("libfstack.so", RTLD_NOW);
	char* errstr = dlerror();
	if (errstr != NULL)
		printf ("A dynamic linking error occurred: (%s)\n", errstr);
	fprintf(stderr, "dlopen is called\n");
	fflush(stderr);
	use_fstack = (handle != NULL);

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
    		ff_bind_ptr = (int (*)(int, const struct sockaddr *a, socklen_t))dlsym(handle, "ff_bind");
    		ff_accept_ptr = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(handle, "ff_accept");
    		ff_listen_ptr = (int (*)(int, int))dlsym(handle, "ff_listen");
    		ff_getsockname_ptr = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(handle, "ff_getsockname");
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
		ff_select_ptr = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *))dlsym(handle, "ff_select");

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
		const int myargc = 5;
		const char *myargv[5];
		const char* proc_type = id == 0 ? "--proc-type=primary" : "--proc-type=secondary";
		char proc_id[16];
		snprintf(proc_id, 15, "--proc-id=%d", id);
		char config[256];
		snprintf(config, 256, "/cb/cs1-job-logs/siemens_logs/systemf98/workdir_vp/config%d.ini", id);
		//myargv[0] = argv[0];
		myargv[0] = "paghpagh";
		myargv[1] = "--conf";
		myargv[2] = config;
		myargv[3] = proc_type;
		myargv[4] = proc_id;
		printf("%s %s\n", proc_type,  proc_id);
		ff_init_ptr(myargc, (char * const)myargv);
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
		ff_getsockopt_ptr = &getsockopt;
    		ff_run_ptr =  &linux_stack_loop;
		ff_ioctl_ptr = &ioctl;
		ff_select_ptr = &select;
	}

	printf("Running the loop\n");
	ff_run_ptr(loop, NULL);

	return 0;
}

