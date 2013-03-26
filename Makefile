.PHONY: all install clean

CC := gcc
LD := gcc

FIND ?= find

ifeq ($(shell uname),Linux)
_L_CAP = -lcap
endif

override LDFLAGS := -lev -lsqlite3 $(_L_CAP) $(LDFLAGS)
override CFLAGS := -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing -O3 -std=gnu11 -pedantic $(CFLAGS)

ifdef DEBUG
override CFLAGS += -O0 -g
endif

all: dhcpd schema.sql

schema.sql: tools/dump-schema
	./tools/dump-schema > $@

tools/dump-schema: tools/dump-schema.o
	$(LD) $(LDFLAGS) -o $@ $^

dhcpd: dhcpd.o argv.o config.o
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) dhcpd
	$(RM) tools/dump-schema
	$(RM) schema.sql
	$(FIND) ./ -name '*.o' -delete

dhcpd.o: dhcp.h array.h argv.h error.h db.h config.h
argv.o: argv.h
config.o: config.h
tools/dump-schema.o: db.h

config.h: argv.h
dhcp.h: array.h

