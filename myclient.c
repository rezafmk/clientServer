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

#define PORT 3675
#define USE_FSTACK 1

// In f-stack mode, run like:
// ./client --conf /data/f-stack/config.ini --proc-type=primary --proc-id=0
int main(int argc, char * const argv[]) {

	int clientSocket, ret;
	struct sockaddr_in serverAddr;
	char buffer[1024];

	void *handle;
	handle = dlopen("libfstack.so", RTLD_NOW);
	fprintf(stderr, "dlopen is called\n");
	fflush(stderr);
	int use_fstack = (handle != NULL);

	int (*ff_init_ptr)(int, char * const);
	int (*ff_socket_ptr)(int, int, int);
	ssize_t (*ff_send_ptr)(int, const void*, size_t, int);
	ssize_t (*ff_recv_ptr)(int, void*, size_t, int);
	int (*ff_connect_ptr)(int, const struct sockaddr *, socklen_t);
	int (*ff_close_ptr)(int);

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
		if (!ff_socket_ptr || !ff_send_ptr || !ff_recv_ptr || !ff_connect_ptr || !ff_close_ptr) {
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

	clientSocket = ff_socket_ptr(AF_INET, SOCK_STREAM, 0);
	if(clientSocket < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Client Socket is created.\n");

	//memset(&serverAddr, '\0', sizeof(serverAddr));
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	//serverAddr.sin_addr.s_addr = inet_addr("10.250.136.19");
	serverAddr.sin_addr.s_addr = inet_addr("10.250.136.21");

	//ret = ff_connect_ptr(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	char myIP[16];
	inet_ntop(AF_INET, &serverAddr.sin_addr, myIP, sizeof(myIP));
	int myPort = ntohs(serverAddr.sin_port);
	printf("Attempting connect to port %d on IP %s\n", myPort, myIP);
	ret = ff_connect_ptr(clientSocket, (struct linux_sockaddr *)&serverAddr, sizeof(serverAddr));
#if 0
	if(ret < 0){
		printf("[-]Error in connection. error code: %d\n", ret);
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

	return 0;
}
