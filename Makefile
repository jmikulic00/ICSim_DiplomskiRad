CC=gcc
CFLAGS=-I/usr/include/SDL2 -Wall -Wextra
LDFLAGS=-lSDL2 -lSDL2_image

all: icsim controls

icsim: icsim.o lib.o
	$(CC) $(CFLAGS) -o icsim icsim.c lib.o $(LDFLAGS)

controls: controls.o
	$(CC) $(CFLAGS) -o controls controls.c lib.o $(LDFLAGS)

lib.o:
	$(CC) lib.c

clean:
	rm -rf icsim controls icsim.o controls.o
