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

override LDFLAGS := $(LDFLAGS) -flto -O3
override CFLAGS := -Wall -Wextra -Werror -fno-strict-aliasing -flto -O3 -std=gnu11 -pedantic $(CFLAGS)
override CPPFLAGS := $(CPPFLAGS)

ifdef DEBUG
override CFLAGS += -O0 -g
endif

all: dhcpd dhcpstress

dhcpd: dhcpd.o argv.o config.o dhcp.o db.o
	$(LD) $(LDFLAGS) -o $@ $^ -lev -lsqlite3 $(L_CAP_NG)

dhcpstress: dhcpstress.o dhcp.o
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) dhcpd dhcpstress
	$(FIND) ./ -name '*.o' -type f -delete

dhcpd.o: array.h dhcp.h argv.h error.h db.h config.h iplist.h
argv.o: argv.h
config.o: config.h
dhcp.o: dhcp.h
db.o: db.h
dhcpstress.o: error.h dhcp.h

dhcp.h: array.h
db.h: iplist.h dhcp.h
config.h: argv.h

