.PHONY: all install clean
.SUFFIXES: .d

CC := gcc
LD := $(CC)
CXX := g++

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

LDFLAGS += -lev
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

LDFLAGS += $(shell pkg-config --libs $(LIBS))
CFLAGS += $(shell pkg-config --cflags $(LIBS))

all: $(BIN)

clean:
	$(RM) dhcpd dhcpstress *.d *.o

$(BIN): $(OBJS)
	$(LD) -o $@ $@.o $(OBJS_UTIL) $(LDFLAGS) $(FLAGS_L)

-include %.d
