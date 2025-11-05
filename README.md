# Pasque

An UDP over HTTP/3 (**[RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)**)
and IP over HTTP/3 implementation
(**[RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)**). Built using
**[Quiche](https://github.com/cloudflare/quiche/)** as the HTTP/3 & QUIC
implementation.

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

    cargo run --bin psq-server

The example server listens on UDP port 443 for incoming HTTP/3 and QUIC
connections. You can change the address and port using the `-a` option. To bind to
multiple addresses, specify the `-a` option multiple times. A common use case is
to bind both IPv4 and IPv6 addresses, for example: `-a 0.0.0.0:443 -a [::]:443`.

The server needs a JSON configuration file that gives links to files containing
TLS certificate and private key are given in a JSON configuration file. The
configuration file is given with `-c` option.
If no config is specified, the example configuration file from
**[server-example.json](src/bin/server-example.json)** (at build time) is used.
It points to an invalid certificate, but can be used for development
and testing, if certificate validation is disabled at client.

**Starting the example client:**

    cargo run --bin psq-client -- -i -d https://localhost

The example program will make a HTTP/3 CONNECT request to set up IP tunnel, in
addition to UDP tunnel. For development and testing, if you are testing against
a server with invalid certificate, use option `--ignore-cert` to disable
certificate check.

## Server configuration

An example server configuration file is provided in
**[server-example.json](src/bin/server-example.json)**. It has a few global
fields defining the server operation:

- **cert_file**: path to the PEM certificate file used in the TLS connection.

- **key_file**: path to the private key needed with the certificate.

- **jwt_secret**: Secret that is used to decode the JWT tokens. This should
  actually be a sufficiently long randomly generated string.

After the global parameters, there are configurations for different endpoints
that the server operates: IP tunnel endpoint (type: `IpEndpoint`), UDP proxy
endpoint (type: `UdpEndpoint`) and an endpoint serving static files (type:
`Files`).

Each endpoint type has the following common configurable fields:

- **path**: the URL path used to access the endpoint.

- **permission**: (Optional) A permission label required in the JWT token for
  access. A token may include one or more such labels to authorize access to
  specific endpoints. If omitted, the endpoint is publicly accessible without
  authentication. If provided and not matched by the token, the request is
  rejected.

### IP Tunnel (IpEndpoint)

The following fields are used to configure an IP tunnel:

- **ifprefix**: Prefix for the names of TUN interfaces created for clients. Each
  client is assigned a unique interface with this prefix (e.g., ifprefix-iN,
  where N is an integer).

- **addresspools**: A list of network prefixes used to assign addresses to
  clients. Each new client receives one address from each specified prefix. This
  allows support for both IPv4 and IPv6 addresses.

- **routes**: Network prefixes advertised to the client as available routes.

### UDP Proxy (UdpEndpoint)

The UDP proxy currently has no configuration fields. All parameters are provided
as URI variables in the HTTP request, as defined in **[RFC 9298]**.

### Static File Sharing (Files)

The `Files` endpoint has a single field:

- **root**: Path to the directory on the server’s file system from which static
  files are served.

[RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298

## Generating JWT tokens

You can use the `gentoken` binary to generate JWT tokens for testing endpoint
authorization with `psq-client`.

Example usage:

    cargo run --bin gentoken -- --sub alice --lifetime 30 --permissions ipauth,regular --secret mysecret

This command generates a token for the subject _alice_, valid for 30 minutes.
The token includes the permission labels `ipauth` and `regular`, which correspond to
those in the example server configuration. The `mysecret` file contains secret,
that must match the secret given in the `jwt_secret` field in the server
configuration, used for encoding and decoding the token.

The token is printed to standard output and can be passed to `psq-client` using
the `--token` option, which adds it to the Authorization header of HTTP
requests.

## Further information

- **[RFC 9298: Proxying UDP in HTTP](https://datatracker.ietf.org/doc/html/rfc9298)**
- **[RFC 9484: Proxying IP in HTTP](https://datatracker.ietf.org/doc/html/rfc9484)**
- **[Masque WG in the IETF](https://datatracker.ietf.org/wg/masque/)**
