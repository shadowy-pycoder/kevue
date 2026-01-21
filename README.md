# kevue - key-value in-memory database

`kevue` is a multithreaded TCP server that maps its endpoints to hash table operations (get/put/delete).

> [!WARNING]
> This project is not in production ready state yet. Moreover, this is my second project in C so expect many bugs, memory leaks with undefined behaviour

## Installation

Create `kevue-server` executable in the `./bin/` directory by running the following command:

```bash
make release
```

## Usage

```bash
./bin/kevue-server -help
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
    -recvb <int>
        Receive buffer size
        Default: 2097152
    -sendb <int>
        Send buffer size
        Default: 2097152
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

### Server

```bash
# make release -B
# make run
# clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_TCMALLOC -ltcmalloc
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
# clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_JEMALLOC -ljemalloc
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
# clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server
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
# clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc
./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 4.928154238s (2127725.61 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 3.767107064s (2783504.64 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.977504761s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.378654754s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.424961659s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000254s
Deleting 10485760 items...
Deleting 10485760 items takes: 4.072044448s (2575060.30 op/sec)

# clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED
./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 4.839803558s (2166567.27 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 3.783049543s (2771774.43 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.811433994s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.365259108s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.383771605s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000041s
Deleting 10485760 items...
Deleting 10485760 items takes: 4.088524518s (2564680.72 op/sec)

# clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_JEMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED
./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 4.842165646s (2165510.39 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 3.757114363s (2790907.86 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.823646134s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.377158592s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.455466494s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000040s
Deleting 10485760 items...
Deleting 10485760 items takes: 4.007769836s (2616357.83 op/sec)
```

## TODO

- [x] Implement basic logic to handle `GET`, `SET`, `DELETE`, hash table operations in memory
- [ ] Add comments and documentation
- [ ] Add tests and benchmarks
- [ ] Make it compilable with C++ compilers
- [ ] Load/save from persistent storage
- [ ] Add more commands
- [ ] Add arena memory allocator
- [ ] Add lock-free hashmap implementation (e.g. Hopscotch hashing )
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
