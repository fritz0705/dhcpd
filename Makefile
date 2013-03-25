.PHONY: all install clean

CC := gcc
LD := gcc
LDFLAGS := -lev -lsqlite3 $(LDFLAGS)
CFLAGS := -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing -O3 -std=gnu99 -g -pedantic $(CFLAGS)

all: dhcpd dhcpd6

dhcpd6:

dhcpd: dhcpd.o
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	$(RM) dhcpd
	$(RM) dhcpd6
	$(RM) *.o

