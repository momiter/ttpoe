ifeq ($(origin CC), default)
CC := gcc
endif
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += -I../include

all: ttp_sock_client ttp_sock_server

ttp_sock_client: ttp_sock_client.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_sock_client.o ttp_sock_common.o

ttp_sock_server: ttp_sock_server.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_sock_server.o ttp_sock_common.o

clean:
	$(RM) *.o *.a ttp_sock_client ttp_sock_server recv_test.txt
