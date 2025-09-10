CC=gcc
CFLAGS=-Iinclude -Wall -Wextra
LDFLAGS=-lpcap

SRC=src/main.c src/capture.c src/parser.c
OBJ=$(SRC:.c=.o)

network-sniffer: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o network-sniffer $(LDFLAGS)

clean:
	rm -f network-sniffer src/*.o

