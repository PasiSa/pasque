# Pasque

An UDP over HTTP/3 (**[RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)**)
and IP over HTTP/3 implementation
(**[RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)**). Built using
**[Quiche](https://github.com/cloudflare/quiche/)** as the HTTP/3 & QUIC
implementation. The project is yet under construction, which probably is obvious
when browsing the code, and some features are yet missing or not yet fully
functional.

## Building and testing

The code is built similarly to most Rust implementations. `cargo build` builds
the binaries, `cargo test` runs a few tests on the implementation. There is an
example client and server that demonstrate how the crate is used. Because the
TUN interface used to implement the IP tunnel requires superuser privileges, the
TUN-related tests are behind "tuntest" feature, so that the other functionality
can be tested with normal user rights. To run full tests:
`sudo cargo test --features tuntest`

**[psq-client.rs](src/bin/psq-client.rs)** and
**[psq-server.rs](src/bin/psq-server.rs)** are simple examples on how to use the
API. They open a UDP tunnel to server host port 9000, and optionally an IP
tunnel forwarding traffic from the TUN interface to the HTTP/3 connection. Note
that the latter requires sudo privileges, and is so far tested only on Linux.

**Starting the example server:**

    cargo run --bin psq-server -- -i 10.76.0.1/24

The example program listens to UDP port 4433 for incoming HTTP/3 and QUIC
connections. `-i` option enables the IP tunnel at given IP address. Clients are
allocated IP addresses from the given IP network, hence also the prefix length
is given.

The server needs a JSON configuration file that gives links to files containing
TLS certificate and private key are given in a JSON configuration file. The
configuration file is given with `-c` option. By default, an example
configuration file **[server-example.rs](src/bin/server-example.rs)** is used,
that contains link to an invalid certificate, but can be used for development
and testing, if certificate validation is disabled at client.

**Starting the example client:**

    cargo run --bin psq-client -- -i -d https://localhost:4433

The example program will make a HTTP/3 CONNECT request to set up IP tunnel. For
development and testing, if you are testing against a server with invalid
certificate, use option `--ignore-cert` to disable certificate check.

## Further information

- **[RFC 9298: Proxying UDP in HTTP](https://datatracker.ietf.org/doc/html/rfc9298)**
- **[RFC 9484: Proxying IP in HTTP](https://datatracker.ietf.org/doc/html/rfc9484)**
- **[Masque WG in IETF](https://datatracker.ietf.org/wg/masque/)**
