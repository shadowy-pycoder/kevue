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

Performed on `13th Gen Intel(R) Core(TM) i7-1355U (12) @ 5.00 GHz` with perfomance mode

### Server

```bash
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
Inserting 10485760 items takes: 2.369143025s (4425971.71 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 1.478306758s (7093088.05 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.628600289s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.291223106s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.313610413s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000154s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.717743429s (6104380.80 op/sec)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED
taskset -c 0 ./bin/kevue-bench-hashmap
Ijnserting 10485760 items...
Inserting 10485760 items takes: 1.693756791s (6190829.79 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 1.047558695s (10009711.20 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.648280134s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.295500887s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.309397667s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000027s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.329503598s (7886973.77 op/sec)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_JEMALLOC -ljemalloc -D__HASHMAP_SINGLE_THREADED
taskset -c 0 ./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 2.078912370s (5043868.20 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 1.047995867s (10005535.64 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.592397845s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.289765484s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.307829373s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000027s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.299129788s (8071372.16 op/sec)

```

## TODO

- [x] Implement basic logic to handle `GET`, `SET`, `DELETE`, hash table operations in memory
- [ ] Add UNIX sockets for local clients
- [ ] Add comments and documentation
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
