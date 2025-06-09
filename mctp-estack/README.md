# Embedded MCTP Stack

[API docs](https://docs.rs/mctp-estack)

This is a MCTP stack suitable for embedded devices.

A `Router` instance handles feeding MCTP packets to and from user
provided MCTP transports, and handles sending receiving MCTP messages
from applications using the `mctp` crate async traits.

Applications using MCTP can create `RouterAsyncListener` and
`RouterAsyncReqChannel` instances.

MCTP bridging between ports is supported by the `Router`.

The core `Stack` handles IO-less MCTP message reassembly and fragmentation,
and MCTP tag tracking. MCTP transport binding packet encoding and decoding is
provided for I2C, USB, and serial.
