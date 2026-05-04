ifeq ($(origin CC), default)
CC := gcc
endif
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += -I../include

all: ttp_sock_client ttp_sock_server ttp_file_send ttp_file_recv ttp_perf_client ttp_perf_server ttp_raw_inject ttp_full_probe

ttp_sock_client: ttp_sock_client.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_sock_client.o ttp_sock_common.o

ttp_sock_server: ttp_sock_server.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_sock_server.o ttp_sock_common.o

ttp_file_send: ttp_file_send.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_file_send.o ttp_sock_common.o

ttp_file_recv: ttp_file_recv.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_file_recv.o ttp_sock_common.o

ttp_perf_client: ttp_perf_client.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_perf_client.o ttp_sock_common.o

ttp_perf_server: ttp_perf_server.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_perf_server.o ttp_sock_common.o

ttp_raw_inject: ttp_raw_inject.o
	$(CC) $(CFLAGS) -o $@ ttp_raw_inject.o

ttp_full_probe: ttp_full_probe.o ttp_sock_common.o
	$(CC) $(CFLAGS) -o $@ ttp_full_probe.o ttp_sock_common.o

clean:
	$(RM) *.o *.a ttp_sock_client ttp_sock_server ttp_file_send ttp_file_recv ttp_perf_client ttp_perf_server ttp_raw_inject ttp_full_probe recv_test.txt
