## tls

A TLS stream library for Carp, built on OpenSSL. Provides `TlsStream`, an
encrypted TCP stream with an API that mirrors
[`TcpStream`](https://github.com/carpentry-org/socket) from the socket library.

## Installation

```clojure
(load "git@github.com:carpentry-org/tls@0.0.1")
```

Requires OpenSSL (or LibreSSL) installed and discoverable via `pkg-config`. On
macOS with Homebrew: `brew install openssl`.

## Usage

### Basic HTTPS GET

```clojure
(match (TlsStream.connect "example.com" 443)
  (Result.Success s)
    (do
      (ignore (TlsStream.send &s "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
      (match (the (Result String String) (TlsStream.read &s))
        (Result.Success body) (println* &body)
        (Result.Error e) (IO.errorln &e))
      (TlsStream.close s))
  (Result.Error e) (IO.errorln &e))
```

### Reading until end of stream

```clojure
(defn read-all [s]
  (let-do [acc @""
           done false]
    (while (not done)
      (let [chunk (the (Result String String) (TlsStream.read s))]
        (match chunk
          (Result.Success data)
            (if (= (String.length &data) 0)
              (set! done true)
              (set! acc (String.concat &[acc data])))
          (Result.Error _) (set! done true))))
    acc))
```

### Sending and reading bytes

```clojure
(let [bytes (Array.copy-map &(fn [c] (Byte.from-int (Char.to-int @c))) &(String.chars req))]
  (TlsStream.send-bytes &s &bytes))

(match (the (Result (Array Byte) String) (TlsStream.read-bytes &s))
  (Result.Success data) (do-something &data)
  _ ())
```

## API

| Function | Purpose |
|----------|---------|
| `TlsStream.connect host port` | Open a TLS connection. Returns `(Result TlsStream String)` |
| `TlsStream.send stream msg` | Send a string. Returns `(Result Int String)` (bytes sent) |
| `TlsStream.send-bytes stream data` | Send a byte array |
| `TlsStream.read stream` | Read up to 4096 bytes as a string |
| `TlsStream.read-bytes stream` | Read up to 4096 bytes as a byte array |
| `TlsStream.read-append stream buf` | Read and append to an existing byte buffer |
| `TlsStream.close stream` | Close, consuming the stream |
| `TlsStream.close! &stream` | Close by reference |
| `TlsStream.set-timeout stream seconds` | Set read/write timeout |

All fallible operations return `(Result T String)`.

## Security defaults

- TLS 1.2 minimum
- System CA verification enforced (`SSL_VERIFY_PEER`)
- Hostname verification via `SSL_set1_host`
- SNI enabled

## Testing

```
carp -x test/tls.carp
```

The test suite hits `example.com:443` and `localhost:1` (for failure cases).

<hr/>

Have fun!
