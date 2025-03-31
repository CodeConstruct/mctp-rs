Management Component Transport Protocol (MCTP) support for Rust
---------------------------------------------------------------

This workspace repository contains a set of crates providing MCTP support,
primarily for use in embedded applications.

Component Crates
----------------

 * [`mctp`](mctp) implements base type and trait definitions

 * [`mctp-linux`](mctp-linux) implements a transport implementation, using the
   Linux kernel MCTP sockets support for message send/receive

 * [`pldm`](pldm) provides Platform Level Data Model (PLDM) base definitions
   on top of the generic MCTP support

 * [`pldm-fw`](pldm-fw) uses the `pldm` base definitions to implement the
   PLDM for Firmware Update protocol as a library. It include a Firmware Device (`fd`)
   responder that can run on embedded devices with `no_std`, and a 
   Update Agent (`ua`) for `std` platforms.

 * [`pldm-fw-cli`](pldm-fw-cli) is a command-line PLDM Firmware Update utility.
   This targets `mctp-linux` though could be adapted to any implementation of the
   `mctp` crate traits.

 * [`mctp-estack`](mctp-estack) is a MCTP stack suitable for embedded devices,
   running `no_std` with fixed allocations.  It includes a MCTP over I2C transport
   handler. The stack handles message fragmentation/reassembly and tag tracking.
   At present routing is left for specific platform code to handle.

 * [`standalone`](standalone) is a `mctp` trait implementation that includes its
   own `mctp-estack` instance, allowing running a standalone MCTP-over-serial
   stack against a Linux TTY (or any other pipe device). This can be used
   for example with QEMU.

Examples
--------

There's a small example MCTP requester in
[mctp-linux/examples](mctp-linux/examples):

```rust
    // Create a new endpoint using the linux socket support
    let mut ep = MctpLinuxEp::new(EID, MCTP_NET_ANY)?;

    // for subsequent use of `ep`, we're just interacting with the
    // mctp::Comm trait, which is independent of the socket support

    // Get Endpoint ID message: command 0x02, no data. Allow the MCTP stack
    // to allocate an owned tag.
    let tx_buf = vec![0x02u8];
    ep.send(MCTP_TYPE_CONTROL, None, &tx_buf)?;

    // Receive a response. We create a 16-byte vec to read into; ep.recv()
    // will return the sub-slice containing just the response data.
    let mut rx_buf = vec![0u8; 16];
    let (rx_buf, eid, tag) = ep.recv(&mut rx_buf)?;
```

There are also some MCTP over serial examples in [standalone/examples](standalone/examples).
