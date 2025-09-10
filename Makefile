CC=gcc
CFLAGS=-Iinclude -Wall -Wextra
LDFLAGS=-lpcap

SRC=src/main.c src/capture.c src/parser.c
OBJ=$(SRC:.c=.o)

nox_sniffer: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o nox_sniffer $(LDFLAGS)

clean:
	rm -f nox_sniffer src/*.o

