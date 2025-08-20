# Embedded MCTP Stack

[API docs](https://docs.rs/mctp-estack)

This is a MCTP stack suitable for embedded devices.
A `async` Router for embassy based applications is available
through the `embassy` feature.

A `Router` instance handles feeding MCTP packets to and from user
provided MCTP transports, and handles sending receiving MCTP messages
from applications using the `mctp` crate async traits.

Applications using MCTP can create `RouterAsyncListener` and
`RouterAsyncReqChannel` instances.

MCTP bridging between ports is supported by the `Router`.

The core `Stack` handles IO-less MCTP message reassembly and fragmentation,
and MCTP tag tracking. MCTP transport binding packet encoding and decoding is
provided for I2C, USB, and serial.

## Features
- `embassy`: async `Router` for [Embassy](https://embassy.dev/)
- `async`: [embedded-io-async](https://docs.rs/embedded-io-async/0.6.1/embedded_io_async/) serial transport binding (enabled by `embassy` feature)
