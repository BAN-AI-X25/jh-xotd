# Usage:
# make			# Compile all binary
# malke clean		# remove all binaries and objects

.PHONY = all clean

CC=gcc
LIBS=-lpthread

SRCS := $(wildcard *.c)
BINS := $(SRCS:%.c=%)
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: ${BINS}

xotd: $(OBJS)
	${CC} -o $@ $< $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	@echo "Cleaning up..."
	rm -rvf *.o $(BINS)
