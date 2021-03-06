CC := gcc
CFLAGS := -Wall -Werror
ARCH32 := -m32
ARCH64 := -m64

all:
	$(CC) $(ARCH32) $(CFLAGS) -o 1.bin 1.c
	$(CC) $(ARCH32) $(CFLAGS) -o 2.bin 2.c
	$(CC) $(ARCH32) $(CFLAGS) -o 3.bin 3.c
	$(CC) $(ARCH32) $(CFLAGS) -o 4.bin 4.c
	$(CC) $(ARCH32) $(CFLAGS) -o 5.bin 5.c
clean:
	rm -rf core *.bin
