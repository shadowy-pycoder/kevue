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
# clang -O3 -flto --march=native Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc
./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 2.838333301s (3694337.09 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 1.879389775s (5579342.90 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.792328717s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.368018760s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.399308250s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000249s
Deleting 10485760 items...
Deleting 10485760 items takes: 2.146867275s (4884214.37 op/sec)

# clang -O3 -flto --march=native Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc -D__HASHMAP_SINGLE_THREADED
./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 2.081931614s (5036553.52 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 1.360377125s (7707980.24 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.784745584s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.368867426s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.385510592s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000039s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.596960224s (6566074.62 op/sec)

# clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_JEMALLOC -ljemalloc -D__HASHMAP_SINGLE_THREADED
./bin/kevue-bench-hashmap
Inserting 10485760 items...
Inserting 10485760 items takes: 2.509616456s (4178232.09 op/sec)
Getting 10485760 items...
Getting 10485760 items takes: 1.344463233s (7799216.63 op/sec)
Fetching 10485760 items...
Fetching 10485760 items takes: 0.721899452s
Fetching 10485760 keys...
Fetching 10485760 keys takes: 0.363816352s
Fetching 10485760 values...
Fetching 10485760 values takes: 0.420513483s
Counting 10485760 entries...
Counting 10485760 entries takes: 0.000000041s
Deleting 10485760 items...
Deleting 10485760 items takes: 1.566462760s (6693909.53 op/sec)

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
