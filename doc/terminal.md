# PTY terminal connection using HTTP/3

This is an experiment demonstrating how an HTTP/3 CONNECT request could be used
to open a pseudoterminal session between a client and a server. Currently, the
endpoint uses the `:protocol` header value "`connect-pty`". The command to be
executed at the server side is specified with the `cmd` query parameter.

There are still some incomplete parts in the implementation, including:

- Proper handling of terminal session closure
- Passing user information (e.g., through a JWT token)

## psqsh client

A simple `psqsh` client binary is provided to test the terminal endpoint.

Example usage:

    cargo run --bin psqsh -- -d https://127.0.0.1 -c "sh -c \"echo Hello\""
    --token MYTOKEN

- `-d` option gives the server address to connect to.

- `-c` specifies the command to execute. If not given, an interactive Bash shell
  is started by default.
