# kevue - key-value in-memory database

`kevue` is a multithreaded TCP server that maps its endpoints to hash table operations (get/put/delete). It implements [Kevue Protocol](PROTOCOL.md).

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
Inserting 10485760 items takes: 63.813164444s (164319.70 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 62.684439796s (167278.51 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 1.376357072s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.386575986s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.411162984s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000161935s
Deleting 10485760 items...
Deleting 10485760 items takes: 63.829875791s (164276.68 req/sec)

# make release -B
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_TCMALLOC -ltcmalloc
./bin/kevue-bench-server
Inserting 10485760 items...
Inserting 10485760 items takes: 123.826780740s (84680.87 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 122.567068650s (85551.20 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 1.832541620s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.518053989s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.549419123s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000103205s
Deleting 10485760 items...
Deleting 10485760 items takes: 122.464984827s (85622.51 req/sec)

# make USE_JEMALLOC=1 USE_TCMALLOC=0 ASAN=0 DEBUG=0
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_JEMALLOC -ljemalloc
./bin/kevue-bench-server
Inserting 10485760 items...
Inserting 10485760 items takes: 119.200026130s (87967.77 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 120.229356448s (87214.64 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 1.969856175s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.542134610s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.543154706s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000169844s
Deleting 10485760 items...
Deleting 10485760 items takes: 125.495996207s (83554.54 req/sec)

# make USE_JEMALLOC=0 USE_TCMALLOC=0 ASAN=0 DEBUG=0
# make run
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server
./bin/kevue-bench-server
Inserting 10485760 items...
Inserting 10485760 items takes: 126.509576145s (82885.11 req/sec)
Getting 10485760 items...
Getting 10485760 items takes: 120.334752530s (87138.25 req/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 1.198423508s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.535705443s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.551398505s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000208824s
Deleting 10485760 items...
Deleting 10485760 items takes: 127.858687401s (82010.54 req/sec)
```

### HashMap

```bash
# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 2.273541346s (4612082.39 op/sec 216 ns/op)
Getting 10485760 items...
Getting 10485760 items takes: 1.447180676s (7245646.78 op/sec 138 ns/op)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.605650347s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.279577792s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.302108685s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000229s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.784692096s (5875388.83 op/sec 170 ns/op)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 1.632071587s (6424816.22 op/sec 155 ns/op)
Getting 10485760 items...
Getting 10485760 items takes: 1.026033423s (10219706.07 op/sec 97 ns/op)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.624026397s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.279553502s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.299064313s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000020s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.306019460s (8028793.08 op/sec 124 ns/op)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_JEMALLOC -ljemalloc -D__HASHMAP_SINGLE_THREADED
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 2.003944935s (5232558.95 op/sec 191 ns/op)
Getting 10485760 items...
Getting 10485760 items takes: 1.017855923s (10301811.64 op/sec 97 ns/op)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.576068544s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.277789404s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.298131536s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000021s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.257090664s (8341291.76 op/sec 119 ns/op)

```

## TODO

- [x] Implement basic logic to handle `GET`, `SET`, `DELETE`, hash table operations in memory
- [x] Add UNIX sockets for local clients
- [x] Add comments and documentation
- [ ] Add tests and benchmarks
- [ ] Make it compilable with C++ compilers
- [ ] Load/save from persistent storage
- [ ] Add more commands, `HSET`, `HGET` and the like
- [ ] Add arena memory allocator
- [ ] Add lock-free hashmap implementation (e.g. Hopscotch hashing)
- [ ] Add installation script

## Contributing

Are you a developer?

- Fork the repository
- Create your feature branch: `git switch -c my-new-feature`
- Commit your changes: `git commit -am 'Add some feature'`
- Push to the branch: `git push origin my-new-feature`
- Submit a pull request

## License

Apache 2.0
