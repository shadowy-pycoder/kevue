# kevue - key-value in-memory database

`kevue` is a multithreaded TCP/UNIX server that maps its endpoints to hash table operations (get/put/delete). It implements [Kevue Protocol](PROTOCOL.md).

> [!WARNING]
> This project is not in production ready state yet. Moreover, this is my second project in C so expect many bugs, memory leaks with undefined behaviour

## Installation

Create `kevue-server` executable in the `./bin/` directory by running the following command:

```bash
make
```

To install system-wide:

```bash
make release
sudo make install
```

## Usage

```bash
./bin/kevue-server -help
 _
| |  _ ____ _   _ _   _  ____
| | / ) _  ) | | | | | |/ _  )
| |< ( (/ / \ V /| |_| ( (/ /
|_| \_)____) \_/  \____|\____)
kevue-server v0.0.1 (built for Linux x86_64)
GitHub: https://github.com/shadowy-pycoder/kevue

Usage: kevue-server [OPTIONS]
OPTIONS:
    -help
        Print this help message and exit
    -host <str>
        Server host
        Default: 0.0.0.0
    -port <str>
        Server port
        Default: 12111
    -unix <str>
        UNIX socket path
        Default: /tmp/kevue.sock
    -recvb <int>
        Receive buffer size
        Default: 2097152
    -sendb <int>
        Send buffer size
        Default: 2097152
    -workers <int>
        TCP server workers
        Default: 1
Compiled with:
KEVUE_TCP_SERVER_WORKERS=1
KEVUE_UNIX_SERVER_WORKERS=1
USE_TCMALLOC
```

Run the server:

```bash
make run
# or ./bin/kevue-server -host 0.0.0.0 -port 12111
```

Compile cli app from `./examples`:

```bash
make examples
```

```bash
./bin/kevue-cli -help
 _
| |  _ ____ _   _ _   _  ____
| | / ) _  ) | | | | | |/ _  )
| |< ( (/ / \ V /| |_| ( (/ /
|_| \_)____) \_/  \____|\____)
kevue-cli v0.0.1 (built for Linux x86_64)
GitHub: https://github.com/shadowy-pycoder/kevue

Usage: kevue-cli [OPTIONS]
OPTIONS:
    -help
        Print this help message and exit
    -host <str>
        Server host
        Default: 0.0.0.0
    -port <str>
        Server port
        Default: 12111
    -unix <str>
        UNIX socket path
        Default:
    -read_timeout <int>
        Read timeout
        Default: 10
    -write_timeout <int>
        Write timeout
        Default: 10
```

Run the client:

```bash
./bin/kevue-cli -host 0.0.0.0 -port 12111
```

```shell
# client console session example
[2026-01-20 00:20:55.179152018Z] INFO: Connected to 0.0.0.0:12111
0.0.0.0:12111> GET hello
(not found)
0.0.0.0:12111> SET hello world
(ok)
0.0.0.0:12111> GET hello
world
0.0.0.0:12111> DEL hello
(ok)
0.0.0.0:12111> GET hello
(not found)
0.0.0.0:12111>
```

In both cases `host` and `port` can be omitted, default values will be used.

Server supports several commands: `GET`, `SET`, `DELETE`, `COUNT`, `ITEMS`, `KEYS`, `VALUES`, `PING` (to test connection), `HELLO` (to establish connection).

## Benchmarks

Performed on `13th Gen Intel(R) Core(TM) i7-1355U (12) @ 5.00 GHz` with perfomance mode

### Server

```bash
# make release -B SINGLE_THREADED_UNIX_SERVER=1
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_unix_server.c -o ./bin/kevue-bench-unix-server -DUSE_TCMALLOC -ltcmalloc
Inserting 10485760 items...
Inserting 10485760 items takes: 45.177852557s (232099.57 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 43.212917678s (242653.37 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.850455614s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.423547706s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.433821851s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000032281s
Deleting 10485760 items...
Deleting 10485760 items takes: 45.741002854s (229242.02 req/sec)

# make release -B
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_TCMALLOC -ltcmalloc
./bin/kevue-bench-server
Inserting 10485760 items...
Inserting 10485760 items takes: 109.514137908s (95748.00 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 105.042856331s (99823.64 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.850709463s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.410204026s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.425641106s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000144120s
Deleting 10485760 items...
Deleting 10485760 items takes: 100.566388810s (104267.04 req/sec)

# make USE_JEMALLOC=1 USE_TCMALLOC=0 ASAN=0 DEBUG=0
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_JEMALLOC -ljemalloc
./bin/kevue-bench-server
Inserting 10485760 items...
Inserting 10485760 items takes: 107.919068392s (97163.18 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 101.324531404s (103486.88 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.878918233s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.399739579s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.414424906s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000050001s
Deleting 10485760 items...
Deleting 10485760 items takes: 105.305730330s (99574.45 req/sec)

# make USE_JEMALLOC=0 USE_TCMALLOC=0 ASAN=0 DEBUG=0
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server
./bin/kevue-bench-server
Inserting 10485760 items...
Inserting 10485760 items takes: 110.801376079s (94635.65 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 109.786227899s (95510.70 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.729023911s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.425375168s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.446152672s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000176884s
Deleting 10485760 items...
Deleting 10485760 items takes: 108.387425218s (96743.33 req/sec)
```

### HashMap

```bash
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 1.966471830s (5332270.64 op/sec 187 ns/op)
Getting 10485760 items...
Getting 10485760 items takes: 1.388914905s (7549605.78 op/sec 132 ns/op)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.469762339s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.276755913s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.304213719s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000214s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.568036623s (6687190.75 op/sec 149 ns/op)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 1.542429654s (6798209.55 op/sec 147 ns/op)
Getting 10485760 items...
Getting 10485760 items takes: 0.935692190s (11206420.35 op/sec 89 ns/op)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.469106122s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.278296601s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.300366370s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000027s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.250820704s (8383103.96 op/sec 119 ns/op)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_JEMALLOC -ljemalloc -D__HASHMAP_SINGLE_THREADED
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 1.604222289s (6536351.02 op/sec 152 ns/op)
Getting 10485760 items...
Getting 10485760 items takes: 0.861201997s (12175726.53 op/sec 82 ns/op)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.404981561s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.248415849s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.266091085s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000027s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.143722737s (9168096.13 op/sec 109 ns/op)

```

## TODO

- [x] Implement basic logic to handle `GET`, `SET`, `DELETE`, hash table operations in memory
- [x] Add UNIX sockets for local clients
- [x] Add comments and documentation
- [x] Add installation script
- [x] Add tests and benchmarks
- [ ] Add arena memory allocator
- [ ] Make it compilable with C++ compilers
- [ ] Load/save from persistent storage
- [ ] Add more commands, `HSET`, `HGET` and the like
- [ ] Add lock-free hashmap implementation (e.g. Hopscotch hashing)
- [ ] Add GUI

## Contributing

Are you a developer?

- Fork the repository
- Create your feature branch: `git switch -c my-new-feature`
- Commit your changes: `git commit -am 'Add some feature'`
- Push to the branch: `git push origin my-new-feature`
- Submit a pull request

## License

Apache 2.0
