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
#include <sys/ioctl.h>

#define PORT 8000
#define MAX_EVENTS 512

/* kevent set */
struct kevent kevSet;
/* events */
//struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;
int epfd;
struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];

int (*ff_init_ptr)(int, char * const);
int (*ff_socket_ptr)(int, int, int);
ssize_t (*ff_send_ptr)(int, const void*, size_t, int);
ssize_t (*ff_recv_ptr)(int, void*, size_t, int);

int (*ff_accept_ptr)(int, struct sockaddr *, socklen_t *);
int (*ff_connect_ptr)(int, const struct sockaddr *, socklen_t);
int (*ff_bind_ptr_fstack)(int, const struct linux_sockaddr *a, socklen_t) = NULL;
int (*ff_bind_ptr_linux)(int, const struct sockaddr *a, socklen_t) = NULL;

//int (*ff_bind_ptr)(int, const struct sockaddr *a, socklen_t);

int ff_bind_ptr(int sockfd, const struct sockaddr *a, socklen_t len) {
	if (ff_bind_ptr_fstack) {
		return ff_bind_ptr_fstack(sockfd, (const struct linux_sockaddr *)a, len);
	} else {
		assert(ff_bind_ptr_linux);
		return ff_bind_ptr_linux(sockfd, a, len);
	}
	return -1;
}



int (*ff_close_ptr)(int);
int (*ff_listen_ptr)(int, int);
int (*ff_getsockname_ptr)(int, struct sockaddr *, socklen_t *);
int (*ff_kevent_ptr)(int, const struct kevent *, int, struct kevent *, int, const struct timespec *);
void (*ff_run_ptr)(loop_func_t, void *);
int (*ff_kqueue_ptr)(void);
int (*ff_epoll_create_ptr)(int);
int (*ff_epoll_ctl_ptr)(int, int, int, struct epoll_event *);
int (*ff_epoll_wait_ptr)(int, struct epoll_event *, int, int);
ssize_t (*ff_read_ptr)(int, void *, size_t);
ssize_t (*ff_write_ptr)(int, const void *, size_t);
int (*ff_fcntl_ptr)(int, int, ...);
int (*ff_ioctl_ptr)(int, unsigned long, ...);
int (*ff_getsockopt_ptr)(int, int, int, void *, socklen_t *);
int (*ff_setsockopt_ptr)(int, int, int, const void*, socklen_t);

int prevnEvent = -1;
int nclientfd = 0;
int firstTime = 1;
char buf[256];
int prioritizeSend = 0;

int loop(void *arg)
{
	if (firstTime) {
		firstTime = 0;
		sockfd = ff_socket_ptr(AF_INET, SOCK_STREAM, 0);
		printf("sockfd:%d\n", sockfd);
		if (sockfd < 0) {
			printf("ff_socket failed\n");
			exit(1);
		}

		int on = 1;
		ff_ioctl_ptr(sockfd, FIONBIO, &on);

		int err = -1;
		socklen_t len = sizeof(int);
		int nodelay = 1;
		int ret = ff_setsockopt_ptr(sockfd, IPPROTO_TCP, TCP_NODELAY, (const void*)&nodelay, len);
		if (ret) {
			ff_close_ptr(sockfd);
			printf("setsockopt errno:%d %s\n", errno, strerror(errno));
			return -3;
		}
		printf("ff_setsockopt_ptr's return value: %d\n", ret);

		struct sockaddr_in my_addr;
		bzero(&my_addr, sizeof(my_addr));
		my_addr.sin_family = AF_INET;
		my_addr.sin_port = htons(PORT);
		my_addr.sin_addr.s_addr = inet_addr("10.254.153.112"); // vps23

		printf("Binding to address..\n");
		ret = ff_bind_ptr(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
		if (ret < 0) {
			printf("ff_bind failed\n");
			exit(1);
		}

		printf("Listening...\n");
		ret = ff_listen_ptr(sockfd, MAX_EVENTS);
		if (ret < 0) {
			printf("ff_listen failed\n");
			exit(1);
		}


		assert((epfd = ff_epoll_create_ptr(10)) > 0);
		ev.data.fd = sockfd;
		ev.events = EPOLLIN | EPOLLOUT;
		ff_epoll_ctl_ptr(epfd, EPOLL_CTL_ADD, sockfd, &ev);
		return 0;
	}
	/* Wait for events to happen */

	int nevents = ff_epoll_wait_ptr(epfd,  events, MAX_EVENTS, 1);
	if (nevents != prevnEvent) {
		printf("nevents: %d\n", nevents);
		prevnEvent = nevents;
	}
	int i;

	for (i = 0; i < nevents; ++i) {
		/* Handle new connect */
		if (events[i].data.fd == sockfd) {
			printf("Accepting a connection\n");
			int nclientfd = ff_accept_ptr(sockfd, NULL, NULL);
			assert(nclientfd > 0);

			socklen_t len = sizeof(int);
			int nodelay = 1;
			int ret = ff_setsockopt_ptr(nclientfd, IPPROTO_TCP, TCP_NODELAY, (const void*)&nodelay, len);
			if (ret) {
				ff_close_ptr(nclientfd);
				printf("setsockopt errno:%d %s\n", errno, strerror(errno));
				return -3;
			}
			printf("ff_setsockopt_ptr's return value: %d\n", ret);

			/* Add to event list */
			ev.data.fd = nclientfd;
			ev.events  = EPOLLIN | EPOLLOUT;
			if (ff_epoll_ctl_ptr(epfd, EPOLL_CTL_ADD, nclientfd, &ev) != 0) {
				printf("ff_epoll_ctl failed:%d, %s\n", errno,
						strerror(errno));
				exit(0);
			}
			printf("Connection accepted\n");
		} else { 
			if (events[i].events & EPOLLERR ) {
				/* Simply close socket */
				ff_epoll_ctl_ptr(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
				ff_close_ptr(events[i].data.fd);
			} else if (events[i].events & EPOLLIN) {
				memset(buf, '\0', 256);
				size_t readlen = ff_read_ptr(events[i].data.fd, buf, sizeof(buf));
				printf("Read this: %s\n", buf);
				prioritizeSend = 1;
			} else if (events[i].events & EPOLLOUT) {
				if (prioritizeSend) {
					ff_write_ptr(events[i].data.fd, buf, 256);
					prioritizeSend = 0;
					printf("Sent this: %s\n", buf);
				}
			} else {
				printf("unknown event: %8.8X\n", events[i].events);
			}
		}
	}
	return 0;
}

void linux_stack_loop(loop_func_t myloop, void* args) {
	while (1) {
		myloop(args);
	}
}


// In f-stack mode, run like:
// ./client --conf /data/f-stack/config.ini --proc-type=primary --proc-id=0
int main(int argc, char * const argv[]) {

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
    		//ff_bind_ptr = (int (*)(int, const struct sockaddr *a, socklen_t))dlsym(handle, "ff_bind");
    		ff_bind_ptr_fstack = (int (*)(int, const struct linux_sockaddr *a, socklen_t))dlsym(handle, "ff_bind");
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

		if (	!ff_socket_ptr ||
			!ff_send_ptr ||
			!ff_recv_ptr ||
			!ff_connect_ptr ||
			!ff_close_ptr ||
			!ff_getsockname_ptr ||
			!ff_bind_ptr_fstack ||
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
#if 1
		const int myargc = 5;
		const char *myargv[5];
		myargv[0] = argv[0];
		myargv[1] = "--conf";
		//myargv[2] = "/root/original_fstack/f-stack/config.ini";
		myargv[2] = "/root/f-stack/config.ini";
		myargv[3] = "--proc-type=primary";
		myargv[4] = "--proc-id=0";
		ff_init_ptr(myargc, (char * const)myargv);
#else
		ff_init_ptr(argc, argv);
#endif
	} else {
		fprintf(stderr, "Using the Linux Kernel based version\n");
    		ff_socket_ptr = &socket;
    		ff_send_ptr = &send;
    		ff_recv_ptr = &recv;
    		ff_connect_ptr = &connect;
    		ff_close_ptr = &close;
    		ff_bind_ptr_linux = &bind;
    		ff_listen_ptr = &listen;
    		ff_accept_ptr = &accept;
    		ff_getsockname_ptr = &getsockname;
		ff_epoll_create_ptr = &epoll_create;
		ff_epoll_ctl_ptr = &epoll_ctl;
		ff_epoll_wait_ptr = &epoll_wait;
		ff_read_ptr = &read;
		ff_write_ptr = &write;
		ff_setsockopt_ptr = &setsockopt;
    		ff_run_ptr =  &linux_stack_loop;
		ff_ioctl_ptr = &ioctl;
	}

	printf("Running the loop\n");
	ff_run_ptr(loop, NULL);

	return 0;
}
