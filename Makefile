CC := gcc
CFLAGS := -Wall -Werror
ARCH32 := -m32
ARCH64 := -m64

all:
	$(CC) $(ARCH32) $(CFLAGS) -o 1.bin 1.c
clean:
	rm -rf core *.bin
