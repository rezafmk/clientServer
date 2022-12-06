CFLAGS += -O3
LIBS+=-ldl

all:
	cc ${CFLAGS} -o server myserver.cc ${LIBS}
	cc ${CFLAGS} -o client myclient.cc ${LIBS}
clean:
	rm -f client server
