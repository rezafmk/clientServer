all:
	gcc -o client -ldl $(shell pkg-config --static --libs libdpdk) myclient.c
	gcc -o server -ldl $(shell pkg-config --static --libs libdpdk) myserver.c
clean:
	rm -f client server
