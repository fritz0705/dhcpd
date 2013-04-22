.PHONY: all install clean

CC := gcc
LD := $(CC)

FIND ?= find

ifeq ($(shell uname),Linux)
WITH_CAP_DROP ?= yes
endif

ifdef WITH_CAP_DROP
L_CAP_NG=$(shell pkg-config --libs libcap-ng)
endif

override LDFLAGS := $(LDFLAGS)
override CFLAGS := -Wall -Wextra -Werror -fno-strict-aliasing -O3 -std=gnu11 -pedantic $(CFLAGS)
override CPPFLAGS := $(CPPFLAGS)

ifdef DEBUG
override CFLAGS += -O0 -g
endif

all: dhcpd dhcpstress dhcpctl schema.sql

schema.sql: tools/dump-schema
	./tools/dump-schema > $@

tools/dump-schema: tools/dump-schema.o
	$(LD) $(LDFLAGS) -o $@ $^

dhcpd: dhcpd.o argv.o config.o dhcp.o db.o
	$(LD) $(LDFLAGS) -lev -lsqlite3 $(L_CAP_NG) -o $@ $^

dhcpstress: dhcpstress.o dhcp.o
	$(LD) $(LDFLAGS) -o $@ $^

dhcpctl: dhcpctl.o db.o
	$(LD) $(LDFLAGS) -lsqlite3 -o $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) dhcpd dhcpstress dhcpctl
	$(RM) tools/dump-schema
	$(RM) schema.sql
	$(FIND) ./ -name '*.o' -type f -delete

fullclean:
	$(FIND) ./ -name '*.db' -type f -delete

dhcpd.o: array.h dhcp.h argv.h error.h db.h config.h iplist.h
argv.o: argv.h
config.o: config.h
dhcp.o: dhcp.h
db.o: db.h
dhcpstress.o: error.h dhcp.h
tools/dump-schema.o: db.h

dhcp.h: array.h
db.h: iplist.h dhcp.h
config.h: argv.h

