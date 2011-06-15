CFLAGS  = -Wall -g

CC=gcc
LD=gcc

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

tdsrelay: tdsrelay.o


clean:
	rm -rf *.o

all: tdsrelay
 
