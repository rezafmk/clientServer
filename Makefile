all:
	gcc -o client -ldl $(shell pkg-config --static --libs libdpdk) myclient.c
	#gcc -o client -ldl $(shell pkg-config --static --libs libdpdk) linuxclient.c
	gcc -o server -ldl $(shell pkg-config --static --libs libdpdk) myserver.c
	gcc -o jclient -ldl $(shell pkg-config --static --libs libdpdk) jclient.c
clean:
	rm -f client server jclient
