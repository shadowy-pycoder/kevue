PROJNAME := kevue
PROJDIR := $(realpath $(CURDIR))
BUILD := $(PROJDIR)/build
BIN := $(PROJDIR)/bin
DOCS := $(PROJDIR)/docs
EXAMPLES := $(PROJDIR)/examples
TESTS := $(PROJDIR)/tests
TARGETS := server
BINARIES := $(addprefix $(BIN)/$(PROJNAME)-,$(TARGETS))
SRC := $(PROJDIR)/src
INCLUDE := $(PROJDIR)/include
LIB := $(PROJDIR)/lib
CC := clang
CFLAGS := -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -Wno-unused-function -Wno-gnu-zero-variadic-macro-arguments -pedantic -std=c2x -march=native
CFLAGS += -Wno-gnu-statement-expression-from-macro-expansion -Wswitch-enum
TCP_SERVER_WORKERS ?= $(shell command -v nproc >/dev/null 2>&1 && nproc || echo 1)
CPPFLAGS := -I$(INCLUDE) -I$(LIB) -D_GNU_SOURCE -DTCP_SERVER_WORKERS=$(TCP_SERVER_WORKERS)
LDFLAGS := -L$(LIB) -Wl,-rpath,$(LIB)
LDLIBS  =
USE_JEMALLOC ?= auto
USE_TCMALLOC ?= auto
DEBUG ?= 1
ASAN ?= 1
HISTORY_PATH ?= $(HOME)/.kevue_history

ifeq ($(DEBUG),1)
  CFLAGS += -ggdb -O0
  CPPFLAGS += -DDEBUG -D__HASHMAP_DETERMINISTIC
else
  CFLAGS += -O3 -flto
  LDFLAGS += -flto
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

.PHONY: default all clean run debug release compile_commands docs examples tests

default: $(BINARIES)
all: default

OBJECTS = $(patsubst $(SRC)/%.c, $(BUILD)/%.o, $(wildcard $(SRC)/*.c))
OBJECTS += $(patsubst $(LIB)/%.c, $(BUILD)/%.o, $(wildcard $(LIB)/*.c))
COMMON_OBJECTS := $(filter-out $(foreach t,$(TARGETS),$(BUILD)/$(t).o),$(OBJECTS))
EXAMPLES_OBJECTS = $(patsubst $(EXAMPLES)/%.c, $(BUILD)/%.o, $(wildcard $(EXAMPLES)/*.c))
HEADERS = $(wildcard $(INCLUDE)/*.h)
HEADERS += $(wildcard $(LIB)/*.h)
EXAMPLE_BINARIES:= $(patsubst $(BUILD)/%.o,$(BIN)/$(PROJNAME)-%,$(EXAMPLES_OBJECTS))

$(BUILD):
	mkdir -p $(BUILD)

$(BIN):
	mkdir -p $(BIN)

$(BUILD)/%.o: $(SRC)/%.c  $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD)/%.o: $(LIB)/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -w -c $< -o $@

$(BUILD)/%.o: $(EXAMPLES)/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PRECIOUS: $(OBJECTS) $(EXAMPLES_OBJECTS) $(FUZZ_OBJECTS)

$(BIN)/$(PROJNAME)-server: LDLIBS += -pthread

$(BIN)/$(PROJNAME)-cli: CPPFLAGS += -DHISTORY_PATH=\"$(HISTORY_PATH)\"

$(BIN)/$(PROJNAME)-%: $(COMMON_OBJECTS) $(BUILD)/%.o | $(BIN)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

run: $(BIN)/$(PROJNAME)-server
	./$(notdir $(BIN))/$(PROJNAME)-server

examples: $(EXAMPLE_BINARIES)

debug:
	$(MAKE) DEBUG=1 default

release:
	$(MAKE) DEBUG=0 ASAN=0 default examples

$(BIN)/kevue-test-fill-server: | $(BIN)
	$(CC) -g3 -Iinclude -Ilib ./src/allocator.c $(TESTS)/test_fill_server.c -o $(BIN)/kevue-test-fill-server -DDEBUG -lprofiler -DUSE_TCMALLOC -ltcmalloc

tests: $(BIN)/kevue-test-fill-server  | $(BIN)
	$(CC) -g3 -fsanitize=thread,undefined -Iinclude -Ilib $(TESTS)/test_crash_threaded_hashmap.c -o $(BIN)/kevue-test-crash-threaded-hashmap -DDEBUG
	$(CC) -g3 -Iinclude -Ilib $(TESTS)/test_request_deserialize.c -o $(BIN)/kevue-test-request-deserialize -DDEBUG


$(BIN)/kevue-bench-server: | $(BIN)
	$(CC) -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o $(BIN)/kevue-bench-server -DUSE_TCMALLOC -ltcmalloc

.PHONY: bench-server
bench-server: $(BIN)/kevue-bench-server  | $(BIN)
	./$(notdir $(BIN))/kevue-bench-server

$(BIN)/kevue-bench-unix-server: | $(BIN)
	$(CC) -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_unix_server.c -o $(BIN)/kevue-bench-unix-server -DUSE_TCMALLOC -ltcmalloc

.PHONY: bench-unix-server
bench-unix-server: $(BIN)/kevue-bench-unix-server  | $(BIN)
	./$(notdir $(BIN))/kevue-bench-unix-server

$(BIN)/kevue-bench-hashmap: | $(BIN)
	$(CC) -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o $(BIN)/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED

.PHONY: bench-hashmap
bench-hashmap: $(BIN)/kevue-bench-hashmap  | $(BIN)
	./$(notdir $(BIN))/kevue-bench-hashmap

.PHONY: benchmarks
benchmarks: $(BIN)/kevue-bench-server $(BIN)/kevue-bench-unix-server $(BIN)/kevue-bench-hashmap

.PHONY: cpuprof
cpuprof: $(BIN)/kevue-test-fill-server | $(BIN)
	CPUPROFILE=cpu.prof $(BIN)/kevue-test-fill-server
	# pprof --web ./cpu.prof

.PHONY: memprof
memprof: $(BIN)/kevue-test-fill-server | $(BIN)
	HEAPPROFILE=mem.prof $(BIN)/kevue-test-fill-server
	# pprof --web ./bin/kevue-test-fill-server ./mem.prof.0001.heap

.PHONY: leakcheck
leakcheck: $(BIN)/kevue-test-fill-server | $(BIN)
	HEAPCHECK=normal $(BIN)/kevue-test-fill-server
	# pprof --inuse_objects --lines --edgefraction=1e-10 --nodefraction=1e-10 --pdf ./bin/kevue-test-fill-server "/tmp/kevue-test-fill-server.<pid>._main_-end.heap" > leak.pdf


AFL_CC          ?= afl-clang-fast
AFL_CFLAGS      := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra
AFL_INCLUDES    := -I$(INCLUDE) -I$(LIB)
FUZZ_BUILD      := $(PROJDIR)/fuzz/build
FUZZ_BIN        := $(PROJDIR)/fuzz/bin
FUZZ_OUT_BASE   := $(PROJDIR)/fuzz/out
FUZZ_SEEDS_BASE := $(PROJDIR)/fuzz/seeds
FUZZ_DICT_BASE  := $(PROJDIR)/fuzz/dict
FUZZ_HARNESS 	:= $(wildcard $(PROJDIR)/fuzz/harness/*.c)
FUZZ_NAMES   	:= $(patsubst $(PROJDIR)/fuzz/harness/%.c,%,$(FUZZ_HARNESS))
FUZZ_OBJS_NAMES := protocol.o buffer.o allocator.o
FUZZ_OBJECTS    := $(addprefix $(FUZZ_BUILD)/,$(FUZZ_OBJS_NAMES))

.PHONY: fuzz-dirs
fuzz-dirs: $(FUZZ_BIN)
	mkdir -p $(FUZZ_BUILD)
	@for h in $(FUZZ_NAMES); do \
	    mkdir -p $(FUZZ_OUT_BASE)/$$h; \
	done

$(FUZZ_BUILD)/%.o: $(SRC)/%.c $(HEADERS) | $(FUZZ_BUILD)
	$(AFL_CC) $(AFL_CFLAGS) $(AFL_INCLUDES) -c $< -o $@

$(FUZZ_BUILD)/fuzz_%.o: $(FUZZ_HARNESS) $(HEADERS) | $(FUZZ_BUILD)
	$(AFL_CC) $(AFL_CFLAGS) $(AFL_INCLUDES) -c $< -o $@

$(FUZZ_BIN):
	mkdir -p $(FUZZ_BIN)

$(FUZZ_BIN)/%: $(FUZZ_BUILD)/%.o $(FUZZ_OBJECTS) | $(FUZZ_BIN)
	$(AFL_CC) $(AFL_CFLAGS) $(AFL_INCLUDES) $^ -o $@

.PHONY: fuzz-build
fuzz-build: fuzz-dirs $(FUZZ_BIN)/fuzz_request $(FUZZ_BIN)/fuzz_response

.PHONY: fuzz-request
fuzz-request: $(FUZZ_BIN)/fuzz_request | fuzz-dirs
	ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:symbolize=0:detect_stack_use_after_return=1:max_malloc_fill_size=$$((1<<30))" \
	AFL_SKIP_CPUFREQ=1 AFL_DEBUG=1 AFL_AUTORESUME=1 afl-fuzz \
		-i $(FUZZ_SEEDS_BASE)/request \
		-o $(FUZZ_OUT_BASE)/request \
		-x $(FUZZ_DICT_BASE)/request/protocol.dict -- $(FUZZ_BIN)/fuzz_request

.PHONY: fuzz-response
fuzz-response: $(FUZZ_BIN)/fuzz_response | fuzz-dirs
	ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:symbolize=0:detect_stack_use_after_return=1:max_malloc_fill_size=$$((1<<30))" \
	AFL_SKIP_CPUFREQ=1 AFL_DEBUG=1 AFL_AUTORESUME=1 afl-fuzz \
		-i $(FUZZ_SEEDS_BASE)/response \
		-o $(FUZZ_OUT_BASE)/response \
		-x $(FUZZ_DICT_BASE)/response/protocol.dict -- $(FUZZ_BIN)/fuzz_response

compile_commands:
	bear -- make --always-make all examples fuzz-build tests benchmarks

docs:
	doxygen

clean:
	rm -rf $(BUILD)
	rm -rf $(BIN)
	rm -rf $(DOCS)
	rm -rf $(FUZZ_OUT_BASE)/*
	rm -rf $(FUZZ_BIN)/*
	rm -rf $(FUZZ_BUILD)/*
	rm -f *.prof
	rm -f *.heap
