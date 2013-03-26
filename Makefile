.PHONY: all install clean

CC := gcc
LD := gcc

ifeq ($(shell uname),Linux)
_L_CAP = -lcap
endif

override LDFLAGS := -lev -lsqlite3 $(_L_CAP) $(LDFLAGS)
override CFLAGS := -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing -O3 -std=gnu99 -pedantic $(CFLAGS)

ifdef DEBUG
override CFLAGS += -O0 -g
endif

all: dhcpd dhcpd6

dhcpd6:

dhcpd: dhcpd.o argv.o
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	$(RM) dhcpd
	$(RM) dhcpd6
	$(RM) *.o

dhcpd.c: dhcp.h array.h argv.h error.h
argv.c: argv.h

