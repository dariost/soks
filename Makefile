CC ?= cc
CFLAGS ?= -O3
LDFLAGS ?=

all:
	$(CC) -o soks $(CFLAGS) -std=c11 $(LDFLAGS) soks.c
