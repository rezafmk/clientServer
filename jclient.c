#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <dlfcn.h>
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

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 3679

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
 
int count = 0;
int main(int argc, char const* argv[])
{

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

    int sock = 0, valread, client_fd;
    struct sockaddr_in serv_addr;
    char* hello = "Hello from client";
    char buffer[1024] = { 0 };
    if ((sock = ff_socket_ptr(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "10.250.136.19", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((client_fd
         = ff_connect_ptr(sock, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    ff_send_ptr(sock, hello, strlen(hello), 0);
    printf("Hello message sent\n");
    valread = ff_read_ptr(sock, buffer, 1024);
    printf("%s\n", buffer);
 
    // closing the connected socket
    ff_close_ptr(client_fd);
    return 0;
}

