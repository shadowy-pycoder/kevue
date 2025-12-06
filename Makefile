PROJNAME := kevue
PROJDIR := $(realpath $(CURDIR))
BUILD := $(PROJDIR)/build
BIN := $(PROJDIR)/bin
TARGETS := server client
SRC := $(PROJDIR)/src
INCLUDE := $(PROJDIR)/include
LIB := $(PROJDIR)/lib
CC := clang
CFLAGS := -ggdb -Wall -Wextra -Wno-unused-function -pedantic -O2 -std=c2x -march=native
CPPFLAGS := -I$(INCLUDE) -I$(LIB) -DDEBUG
LDFLAGS := -L$(LIB) -Wl,-rpath,$(LIB)
LDLIBS  =

.PHONY: default all clean run compile_commands

default: $(TARGETS)
all: default

OBJECTS := $(patsubst $(SRC)/%.c, $(BUILD)/%.o, $(wildcard $(SRC)/*.c))
COMMON_OBJECTS := $(filter-out $(foreach t,$(TARGETS),$(BUILD)/$(t).o),$(OBJECTS))
HEADERS := $(wildcard $(INCLUDE)/*.h)
HEADERS += $(wildcard $(LIB)/*.h)

$(BUILD):
	mkdir -p $(BUILD)

$(BIN):
	mkdir -p $(BIN)

$(BUILD)/%.o: $(SRC)/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PRECIOUS: $(TARGETS) $(OBJECTS)

$(TARGETS): $(OBJECTS) | $(BIN)
	$(CC) $(COMMON_OBJECTS) $(BUILD)/$@.o $(LDFLAGS) $(LDLIBS) -o $(BIN)/$(PROJNAME)-$@

run: $(TARGETS)
	./$(notdir $(BIN))/kevue-server

clean:
	rm -rf $(BUILD)
	rm -rf $(BIN)

compile_commands:
	bear -- make --always-make
