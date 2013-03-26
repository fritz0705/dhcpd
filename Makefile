.PHONY: all install clean

CC := gcc
LD := $(CC)

FIND ?= find

ifeq ($(shell uname),Linux)
_L_CAP = -lcap
endif

override LDFLAGS := -lev -lsqlite3 $(_L_CAP) $(LDFLAGS)
override CFLAGS := -Wall -Werror -fno-strict-aliasing -O3 -std=gnu11 -pedantic $(CFLAGS)

ifdef DEBUG
override CFLAGS += -O0 -g
endif

all: dhcpd dhcpstress schema.sql

schema.sql: tools/dump-schema
	./tools/dump-schema > $@

tools/dump-schema: tools/dump-schema.o
	$(LD) $(LDFLAGS) -o $@ $^

dhcpd: dhcpd.o argv.o config.o dhcp.o
	$(LD) $(LDFLAGS) -o $@ $^

dhcpstress: dhcpstress.o dhcp.o
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) dhcpd
	$(RM) tools/dump-schema
	$(RM) schema.sql
	$(FIND) ./ -name '*.o' -delete

dhcpd.o: dhcp.h array.h argv.h error.h db.h config.h iplist.h
dhcp.o: dhcp.h
argv.o: argv.h
config.o: config.h
tools/dump-schema.o: db.h

config.h: argv.h
dhcp.h: array.h

