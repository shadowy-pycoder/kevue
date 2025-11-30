PROJDIR := $(realpath $(CURDIR))
PROJNAME = $(notdir $(PROJDIR))
BUILD = $(PROJDIR)/build
BIN = $(PROJDIR)/bin
TARGET = $(BIN)/$(PROJNAME)
SRC = $(PROJDIR)/src
INCLUDE = $(PROJDIR)/include
LIB = $(PROJDIR)/lib
CC = clang
CFLAGS = -ggdb -Wall -Wextra -Werror -pedantic -O2 -std=c2x -march=native
CPPFLAGS = -I$(INCLUDE) -I$(LIB)
LDFLAGS = -L$(LIB) -Wl,-rpath,$(LIB)
LDLIBS  =

.PHONY: default all clean run

default: $(TARGET)
all: default

OBJECTS = $(patsubst $(SRC)/%.c, $(BUILD)/%.o, $(wildcard $(SRC)/*.c))
HEADERS = $(wildcard $(INCLUDE)/*.h)
HEADERS += $(wildcard $(LIB)/*.h)
$(info    HEADERS is $(HEADERS))

$(BUILD)/%.o: $(SRC)/%.c $(HEADERS)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	mkdir -p $(BIN)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

run: $(TARGET)
	./$(notdir $(BIN))/$(PROJNAME)

clean:
	rm -rf $(BUILD)
	rm -rf $(BIN)

