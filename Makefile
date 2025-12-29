PROJNAME := kevue
PROJDIR := $(realpath $(CURDIR))
BUILD := $(PROJDIR)/build
BIN := $(PROJDIR)/bin
TARGETS := server client
BINARIES := $(addprefix $(BIN)/$(PROJNAME)-,$(TARGETS))
SRC := $(PROJDIR)/src
INCLUDE := $(PROJDIR)/include
LIB := $(PROJDIR)/lib
CC := clang
CFLAGS := -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -Wno-unused-function -Wno-gnu-zero-variadic-macro-arguments -pedantic -std=c2x -march=native
CFLAGS += -Wno-gnu-statement-expression-from-macro-expansion
CPPFLAGS := -I$(INCLUDE) -I$(LIB) -D_GNU_SOURCE
LDFLAGS := -L$(LIB) -Wl,-rpath,$(LIB)
LDLIBS  =
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
  USE_TCMALLOC := no
endif

ifeq ($(USE_TCMALLOC),auto)
  ifeq ($(shell pkg-config --exists libtcmalloc && echo yes),yes)
    USE_TCMALLOC := yes
  else
    USE_TCMALLOC := no
  endif
endif

ifeq ($(USE_TCMALLOC),yes)
  CPPFLAGS  += -DUSE_TCMALLOC
  ifeq ($(DEBUG), 1)
    LDLIBS  += -ltcmalloc_debug
  else
    LDLIBS  += -ltcmalloc
  endif
endif

.PHONY: default all clean run debug release compile_commands

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

compile_commands:
	bear -- make --always-make
