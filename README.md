# kevue - key-value in-memory database

`kevue` is a multithreaded TCP server and client that maps its endpoints to hash table operations (get/put/delete).

> [!WARNING]
> This project is not in production ready state yet. Moreover, this is my second project in C so expect many bugs, memory leaks with undefined behaviour

## Installation

Create `kevue-server` and `kevue-client` executables in the `./bin/` directory by running the following command:

```shell
make release
```

## Usage

Run the server:

```shell
make run
# or ./bin/kevue-server 0.0.0.0 12111
```

Run the client:

```shell
./bin/kevue-client 0.0.0.0 12111
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
