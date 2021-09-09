CC=gcc
LD=gcc
CFLAGS=-g -Wall -DLOG_USE_COLOR
INC=-I../ext

all: cp

.c.o:
	$(CC) $(CFLAGS) $(INC) -c $<

cp:  control_plane.o log.o
	$(LD) -o $@ control_plane.o log.o

clean:
	rm -f *.o cp
