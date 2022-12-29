# Makefile for backdoor program

CC=gcc -g
CLIB=-pthread -lpcap

client:
	$(CC) -o client.o client.c raw_socket.c pkt_sniff.c crypto.c $(CLIB)

target:
	$(CC) -o target.o target.c raw_socket.c pkt_sniff.c command.c crypto.c inot.c $(CLIB)

clean:
	rm -f *.o
