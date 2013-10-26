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
override CFLAGS := -Wall -Wextra -Werror -fno-strict-aliasing -flto -O3 -std=c11 -pedantic $(CFLAGS)
override CPPFLAGS := $(CPPFLAGS)

ifdef DEBUG
override CFLAGS += -O0 -g
endif

all: dhcpd

dhcpd: src/dhcpd.o src/dhcp.o src/tools.o
	$(LD) $(LDFLAGS) -o $@ $^ -ljansson -lev -llmdb $(L_CAP_NG)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) dhcpd
	$(FIND) ./src/ -name '*.o' -type f -delete

src/dhcpd.o: src/dhcp.h src/error.h src/tools.h
src/dhcp.o: src/dhcp.h
src/tools.o: src/tools.h

