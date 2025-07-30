Management Component Transport Protocol (MCTP) support for Rust
---------------------------------------------------------------

This workspace repository contains a set of crates providing MCTP support,
primarily for use in embedded applications.

Component Crates
----------------

 * [`mctp`](mctp) implements base type and trait definitions.

 * [`mctp-linux`](mctp-linux) implements a transport implementation, using the
   Linux kernel MCTP sockets support for message send/receive

 * [`pldm`](pldm) provides Platform Level Data Model (PLDM) base definitions
   on top of the generic MCTP support

 * [`pldm-fw`](pldm-fw) uses the `pldm` base definitions to implement the
   PLDM for Firmware Update protocol as a library. It include a Firmware Device (`fd`)
   responder that can run on embedded devices with `no_std`, and an
   Update Agent (`ua`) for `std` platforms.

 * [`pldm-fw-cli`](pldm-fw-cli) is a command-line PLDM Firmware Update utility.
   This targets `mctp-linux` though could be adapted to any implementation of the
   `mctp` crate traits.

 * [`mctp-estack`](mctp-estack) is a MCTP stack suitable for embedded devices,
   running `no_std` with fixed allocations. 
   The stack handles message fragmentation/reassembly and tag tracking.
   The crate's `Router` can be used by async MCTP applications to interface with
   multiple transport ports, and handles MCTP bridging.
   It includes built-in MCTP transport handling for I2C, USB, and serial.

   `mctp-estack` includes a minimal MCTP control protocol implementation.

 * [`mctp-usb-embassy`](mctp-usb-embassy) is a MCTP over USB transport for 
   `embassy-usb`.

 * [`standalone`](standalone) is a `mctp` trait implementation that includes its
   own `mctp-estack` instance, allowing running a standalone MCTP-over-serial
   stack against a Linux TTY (or any other pipe device). This can be used
   for example with QEMU.

API Documentation
-----------------

   [`mctp`](https://docs.rs/mctp/)
   [`mctp-linux`](https://docs.rs/mctp-linux/)
   [`pldm`](https://docs.rs/pldm/)
   [`pldm-fw`](https://docs.rs/pldm-fw/)
   [`mctp-estack`](https://docs.rs/mctp-estack/)
   [`mctp-usb-embassy`](https://docs.rs/mctp-usb-embassy)

Examples
--------

There's a small example MCTP requester in
[mctp-linux/examples](mctp-linux/examples):

```rust
    // Create a new endpoint using the linux socket support
    let mut ep = MctpLinuxReq::new(EID, None)?;

    // for subsequent use of `ep`, we're just interacting with the
    // mctp::ReqChannel trait, which is independent of the socket support

    // Get Endpoint ID message: command 0x02, no data. Allow the MCTP stack
    // to allocate an owned tag.
    let tx_buf = vec![0x02u8];
    ep.send(MCTP_TYPE_CONTROL, &tx_buf)?;

    // Receive a response. We create a 16-byte vec to read into; ep.recv()
    // will return the sub-slice containing just the response data.
    let mut rx_buf = vec![0u8; 16];
    let (typ, ic, rx_buf) = ep.recv(&mut rx_buf)?;
```

There are also some MCTP over serial examples in [standalone/examples](standalone/examples).

Contributing
------------
If you wish to contribute, please see the [contribution guidelines](CONTRIBUTING.md).
