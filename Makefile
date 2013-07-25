.PHONY: all install clean
.SUFFIXES: .d

CC := gcc
LD := $(CC)
CXX := g++

FIND ?= find
GREP ?= grep

PKGCONFIG ?= pkg-config

ifdef DEBUG
LDFLAGS += -g -O0
CFLAGS += -g -O0
CXXFLAGS += -g -O0
else
LDFLAGS += -O3 -flto
CFLAGS += -O3 -flto
CXXFLAGS += -O3 -flto
endif

LDFLAGS +=
CFLAGS += -Wall -Wextra -Werror -std=c11 -pedantic -fno-strict-aliasing
CXXFLAGS += -Wall -Wextra -Werror -std=c++11 -pedantic -fno-strict-aliasing

SRCS := $(wildcard *.c)
SRCS_MAIN := $(shell $(GREP) -l 'int main' $(SRCS))
SRCS_UTIL := $(filter-out $(SRCS_MAIN), $(SRCS))

OBJS := $(patsubst %.c,%.o,$(SRCS))
OBJS_MAIN := $(patsubst %.c,%.o,$(SRCS_MAIN))
OBJS_UTIL := $(patsubst %.c,%.o,$(SRCS_UTIL))

BIN := $(patsubst %.c,%,$(shell $(GREP) -l 'int main' $(SRCS_MAIN)))

LIBS += libcap-ng
#Unfortunately not found by pkg-config on Ubuntu 13.04
#LIBS += libev

FLAGS_L = $(shell pkg-config --libs $(LIBS))
FLAGS_C = $(shell pkg-config --cflags $(LIBS))

#Work-around for Ubuntu 13.04
FLAGS_L += -lev
FLAGS_C +=

all: $(BIN)

clean:
	$(RM) dhcpd dhcpstress
	$(FIND) ./ -name '*.d' -type f -delete
	$(FIND) ./ -name '*.o' -type f -delete

$(BIN): $(OBJS)
	$(LD) -o $@ $@.o $(OBJS_UTIL) $(LDFLAGS) $(FLAGS_L)

%.d:

%.d: %.c
	$(CC) $(CFLAGS) -M -o $@ $<

%.d: %.cpp
	$(CXX) $(CXXFLAGS) -M -o $@ $<

%.o:

%.o: %.c %.d
	$(CC) -o $@ $(CFLAGS) $(FLAGS_C) -c $<

%.o: %.cpp %.d
	$(CXX) $(CXXFLAGS) -o $@ -c $<

-include %.d
