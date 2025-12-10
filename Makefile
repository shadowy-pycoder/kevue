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
CFLAGS := -ggdb -Wall -Wextra -Wno-unused-function -Wno-gnu-zero-variadic-macro-arguments -pedantic -O2 -std=c2x -march=native
CPPFLAGS := -I$(INCLUDE) -I$(LIB) -DDEBUG -D_GNU_SOURCE
LDFLAGS := -L$(LIB) -Wl,-rpath,$(LIB)
LDLIBS  =

.PHONY: default all clean run compile_commands

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
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PRECIOUS: $(OBJECTS)

$(BIN)/$(PROJNAME)-%: $(COMMON_OBJECTS) $(BUILD)/%.o | $(BIN)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

run: $(BIN)/$(PROJNAME)-server
	./$(notdir $(BIN))/$(PROJNAME)-server

clean:
	rm -rf $(BUILD)
	rm -rf $(BIN)

compile_commands:
	bear -- make --always-make
