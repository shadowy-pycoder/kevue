# Kevue Protocol

## Overview

Kevue Protocol is a binary request/response protocol for a key-value database.
The protocol is connection-oriented and transport-agnostic (TCP, UNIX sockets, etc).

All length fields MUST be encoded in network byte order (big-endian).

### Constants

Magic byte `0x22` (`"` in ASCII) is a starting byte in each request and response.

### Commands

| Command  | Description                                                         |
| -------- | ------------------------------------------------------------------- |
| `HELLO`  | Performs initial handshake with the server.                         |
| `GET`    | Retrieves the value associated with a given key.                    |
| `SET`    | Stores a value under a specified key, replacing any existing value. |
| `DEL`    | Removes a key and its associated value from the database.           |
| `PING`   | Checks server availability, returns a simple (echoed) response.     |
| `COUNT`  | Returns the total number of key-value pairs currently stored.       |
| `ITEMS`  | Returns all key-value pairs stored in the database.                 |
| `KEYS`   | Returns a list of all keys in the database.                         |
| `VALUES` | Returns a list of all values stored in the database.                |

All commands are case-insensitive (e.g. `get`, `GET`, `gET` will do).

### Error codes

| Code | Name                           | Description               |
| ---: | ------------------------------ | ------------------------- |
|    0 | `KEVUE_ERR_OK`                 | OK                        |
|    1 | `KEVUE_ERR_INCOMPLETE_READ`    | Reading was not complete  |
|    2 | `KEVUE_ERR_MAGIC_BYTE_INVALID` | Magic byte is invalid     |
|    3 | `KEVUE_ERR_UNKNOWN_COMMAND`    | Unknown command           |
|    4 | `KEVUE_ERR_LEN_INVALID`        | Length is invalid         |
|    5 | `KEVUE_ERR_NOT_FOUND`          | Not found                 |
|    6 | `KEVUE_ERR_READ_FAILED`        | Failed reading message    |
|    7 | `KEVUE_ERR_WRITE_FAILED`       | Failed writing message    |
|    8 | `KEVUE_ERR_READ_TIMEOUT`       | Timed out reading message |
|    9 | `KEVUE_ERR_WRITE_TIMEOUT`      | Timed out writing message |
|   10 | `KEVUE_ERR_EOF`                | Peer closed connection    |
|   11 | `KEVUE_ERR_HANDSHAKE`          | Handshake failed          |
|   12 | `KEVUE_ERR_OPERATION`          | Operation failed          |
|   13 | `KEVUE_ERR_PAYLOAD_INVALID`    | Payload is invalid        |

## Request

### Structure

| Field     | Size     | Type   | Description                          |
| --------- | -------- | ------ | ------------------------------------ |
| magic     | 1 byte   | uint8  | Must equal `0x22`                    |
| total_len | 4 bytes  | uint32 | Total request size (including magic) |
| cmd_len   | 1 byte   | uint8  | Length of command string             |
| command   | cmd_len  | ASCII  | Command name (case-insensitive)      |
| payload   | variable | bytes  | Command specific data                |

### Payload

#### `GET`/`DEL` Payload

| Field   | Size    | Type   | Description   |
| ------- | ------- | ------ | ------------- |
| key_len | 2 bytes | uint16 | Length of key |
| key     | key_len | bytes  | Key data      |

#### `SET` Payload

| Field     | Size      | Type   | Description     |
| --------- | --------- | ------ | --------------- |
| key_len   | 2 bytes   | uint16 | Length of key   |
| key       | key_len   | bytes  | Key data        |
| value_len | 2 bytes   | uint16 | Length of value |
| value     | value_len | bytes  | Value data      |

#### `PING` Payload

If request contain message it should be put in `key` field with `key_len` bytes:

| Field   | Size    | Type   | Description       |
| ------- | ------- | ------ | ----------------- |
| key_len | 2 bytes | uint16 | Length of message |
| key     | key_len | bytes  | Message data      |

Otherwise, `key_len` MUST be equal to 0

#### Other commands

Commands `HELLO`, `COUNT`, `ITEMS`, `KEYS`, `VALUES` do not contain request payload except for `key_len` equal to 0

### Serialization

All integers representing length must be converted to network byte order. `Magic` byte and `total_len` should be calculated during serialization process.If caller provided `total_len`, it should be checked against calculated and `KEVUE_ERR_LEN_INVALID` should be returned in case of inequality.

`KEVUE_ERR_LEN_INVALID` should be returned in case on any invalid length. Checking should be command specific, for example `GET` command should contain key with length greater than 0, `SET` also need to contain value. Command length should always be greater than 0.

`KEVUE_ERR_PAYLOAD_INVALID` should be returned in case of empty key or value (assuming `key_len` > 0 or `value_len` > 0) This error also returned when `key_len` is equal to 0 and command expecting payload.

In case of unknown command `KEVUE_ERR_UNKNOWN_COMMAND` is returned.

On success, `KEVUE_ERR_OK` is returned.

### Deserialization

All integers representing length must be converted to machine byte order.

`KEVUE_ERR_INCOMPLETE_READ` is returned when the number of bytes received is less than 5 (magic byte + 4 bytes of `total_len`) or `total_len` is bigger than buffer size. This error tells the caller to continue reading normally.

`KEVUE_ERR_MAGIC_BYTE_INVALID` should be returned in case of first byte not being equal to `0x22`.

`KEVUE_ERR_LEN_INVALID` should be returned in case on any invalid length. Checking should be command specific.

On success, `KEVUE_ERR_OK` is returned.

## Response

### Structure

| Field     | Size      | Type   | Description                           |
| --------- | --------- | ------ | ------------------------------------- |
| magic     | 1 byte    | uint8  | Must equal `0x22`                     |
| total_len | 8 bytes   | uint64 | Total response size (including magic) |
| cmd_len   | 1 byte    | uint8  | Length of command string              |
| command   | cmd_len   | ASCII  | Command name (case-insensitive)       |
| error     | 1 byte    | uint8  | Error code                            |
| value_len | 8 bytes   | uint64 | Length of reply data                  |
| value     | value_len | bytes  | Command specific data                 |

When `error` field is not equal 0 (`KEVUE_ERR_OK`), `value_len` MUST be equal to 0.

### Payload

#### `HELLO`/`SET`/`DEL` Payload

Do not contain response payload in `value` field, `value_len` MUST be equal to 0

#### `GET` Payload

`value` field contain actual value bytes

#### `PING` Payload

Payload depends on previous request, it either contains request message or, in case request message is empty, arbitrary data (e.g. `PONG` string)

#### `COUNT` Payload

Payload contains number of key-value pairs in database (uint64 in network byte order)

#### `ITEMS`/`KEYS`/`VALUES` Payload

Payload contains 8 byte length prefixed keys, values or both depending on command

### Serialization

Same logic as in request serialization, but also in case of invalid error code `KEVUE_ERR_PAYLOAD_INVALID` should be returned.

### Deserialization

Same logic as in request deserialization.

## Examples

[Request](./fuzz/seeds/request/)
[Response](./fuzz/seeds/response/)
