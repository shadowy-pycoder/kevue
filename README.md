# kevue - key-value in-memory database

`kevue` is a multithreaded TCP server that maps its endpoints to hash table operations (get/put/delete).

> [!WARNING]
> This project is not in production ready state yet. Moreover, this is my second project in C so expect many bugs, memory leaks with undefined behaviour

## Installation

Create `kevue-server` executable in the `./bin/` directory by running the following command:

```shell
make release
```

## Usage

Run the server:

```shell
make run
# or ./bin/kevue-server 0.0.0.0 12111
```

Compile cli app from `./examples`:

```shell
make examples
```

Run the client:

```shell
./bin/kevue-cli 0.0.0.0 12111
```

```shell
# client console session example
INFO: Connected to 0.0.0.0:12111
0.0.0.0:12111> get hello
ERROR: main: Not found
0.0.0.0:12111> set hello world
OK
0.0.0.0:12111> get hello
world
0.0.0.0:12111> del hello
OK
0.0.0.0:12111> get hello
ERROR: main: Not found
0.0.0.0:12111>
```

In both cases `host` and `port` can be omitted, default values will be used.

Server supports several commands: `GET`, `SET`, `DELETE`, `PING` (to test connection), `HELLO` (to establish connection).

## Benchmarks

```shell
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

## TODO

- [x] Implement basic logic to handle `GET`, `SET`, `DELETE`, hash table operations in memory
- [ ] Add comments and documentation
- [ ] Add tests and benchmarks
- [ ] Make it compilable with C++ compilers
- [ ] Load/save from persistent storage
- [ ] Add more commands
- [ ] Add arena memory allocator
- [ ] Add lock-free hashmap implementation (e.g. Hopscotch hashing )

## Contributing

Are you a developer?

- Fork the repository
- Create your feature branch: `git switch -c my-new-feature`
- Commit your changes: `git commit -am 'Add some feature'`
- Push to the branch: `git push origin my-new-feature`
- Submit a pull request

## License

Apache 2.0
