CC = gcc
CFLAGS = -O3
SRCS = src/main.c src/sha256.c
OBJS = $(SRCS:.c=.o)
MAIN = sha256

.PHONY: build clean

build: $(MAIN)
	@echo Compilation finished

$(MAIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(MAIN) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $<  -o $@

clean:
	$(RM) src/*.o *~ $(MAIN)
