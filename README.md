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

**Starting the server:**

    cargo run --bin psq-server

The example program listens
to UDP port 4433 for incoming HTTP/3 and QUIC connections.

Starting the client:

    cargo run --bin psq-client -d https://localhost:4433/ip

The example program will make a HTTP/3 CONNECT request to set up IP tunnel.

See **[psq-client.rs](src/bin/psq-client.rs)** and
**[psq-server.rs](src/bin/psq-server.rs)** for simple examples how to use
the API.

## Further information

- **[RFC 9298: Proxying UDP in HTTP](https://datatracker.ietf.org/doc/html/rfc9298)**
- **[RFC 9484: Proxying IP in HTTP](https://datatracker.ietf.org/doc/html/rfc9484)**
- **[Masque WG in IETF](https://datatracker.ietf.org/wg/masque/)**
