# Embedded MCTP Stack

[API docs](https://docs.rs/mctp-estack)

This is a MCTP stack suitable for embedded devices.
A `async` Router for [Embassy](https://embassy.dev/) (or other _async runtime_)
based applications is available through the `async` feature.

A `Router` instance handles feeding MCTP packets to and from user
provided MCTP transports, and handles sending receiving MCTP messages
from applications using the `mctp` crate _async_ traits.

Applications using MCTP can create `RouterAsyncListener` and
`RouterAsyncReqChannel` instances.

MCTP bridging between ports is supported by the `Router`.

The core `Stack` handles IO-less MCTP message reassembly and fragmentation,
and MCTP tag tracking. MCTP transport binding packet encoding and decoding is
provided for I2C, USB, and serial.

## Features
- `async`: _async_ router implementing `mctp` crate _async_ traits
