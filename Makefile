PROJNAME := kevue
PROJDIR := $(realpath $(CURDIR))
BUILD := $(PROJDIR)/build
BIN := $(PROJDIR)/bin
DOCS := $(PROJDIR)/docs
TARGETS := server client
BINARIES := $(addprefix $(BIN)/$(PROJNAME)-,$(TARGETS))
SRC := $(PROJDIR)/src
INCLUDE := $(PROJDIR)/include
LIB := $(PROJDIR)/lib
CC := clang
CFLAGS := -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -Wno-unused-function -Wno-gnu-zero-variadic-macro-arguments -pedantic -std=c2x -march=native
CFLAGS += -Wno-gnu-statement-expression-from-macro-expansion -Wswitch-enum
SERVER_WORKERS ?= $(shell command -v nproc >/dev/null 2>&1 && nproc || echo 1)
CPPFLAGS := -I$(INCLUDE) -I$(LIB) -D_GNU_SOURCE -DSERVER_WORKERS=$(SERVER_WORKERS)
LDFLAGS := -L$(LIB) -Wl,-rpath,$(LIB)
LDLIBS  =
USE_JEMALLOC ?= auto
USE_TCMALLOC ?= auto
DEBUG ?= 1
ASAN ?= 1

ifeq ($(DEBUG),1)
  CFLAGS += -ggdb -O0
  CPPFLAGS += -DDEBUG
else
  CFLAGS += -Os
endif

ifeq ($(ASAN),1)
  CFLAGS += -fsanitize=address,undefined -fsanitize=bounds -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined -fsanitize=bounds -fno-omit-frame-pointer
  USE_TCMALLOC := 0
  USE_JEMALLOC := 0
endif


ifeq ($(USE_TCMALLOC),auto)
  ifeq ($(shell pkg-config --exists libtcmalloc && echo yes),yes)
    USE_TCMALLOC := 1
    USE_JEMALLOC := 0
  else
    USE_TCMALLOC := 0
  endif
endif

ifeq ($(USE_TCMALLOC),1)
  CPPFLAGS  += -DUSE_TCMALLOC
  ifeq ($(DEBUG), 1)
    LDLIBS  += -ltcmalloc_debug
  else
    LDLIBS  += -ltcmalloc
  endif
endif

ifeq ($(USE_JEMALLOC),auto)
  ifeq ($(shell pkg-config --exists jemalloc && echo yes),yes)
    USE_JEMALLOC := 1
  else
    USE_JEMALLOC := 0
  endif
endif

ifeq ($(USE_JEMALLOC),1)
  CPPFLAGS  += -DUSE_JEMALLOC
  LDLIBS  += -ljemalloc
endif

.PHONY: default all clean run debug release compile_commands docs

default: $(BINARIES)
all: default

OBJECTS = $(patsubst $(SRC)/%.c, $(BUILD)/%.o, $(wildcard $(SRC)/*.c))
OBJECTS += $(patsubst $(LIB)/%.c, $(BUILD)/%.o, $(wildcard $(LIB)/*.c))
COMMON_OBJECTS := $(filter-out $(foreach t,$(TARGETS),$(BUILD)/$(t).o),$(OBJECTS))
HEADERS = $(wildcard $(INCLUDE)/*.h)
HEADERS += $(wildcard $(LIB)/*.h)


$(BUILD):
	mkdir -p $(BUILD)

$(BIN):
	mkdir -p $(BIN)

$(BUILD)/%.o: $(SRC)/%.c  $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD)/%.o: $(LIB)/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -w -c $< -o $@

.PRECIOUS: $(OBJECTS)

$(BIN)/$(PROJNAME)-server: LDLIBS += -pthread

$(BIN)/$(PROJNAME)-%: $(COMMON_OBJECTS) $(BUILD)/%.o | $(BIN)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

run: $(BIN)/$(PROJNAME)-server
	./$(notdir $(BIN))/$(PROJNAME)-server

debug:
	$(MAKE) DEBUG=1

release:
	$(MAKE) DEBUG=0 ASAN=0

clean:
	rm -rf $(BUILD)
	rm -rf $(BIN)
	rm -rf $(DOCS)

compile_commands:
	bear -- make --always-make

docs:
	doxygen
