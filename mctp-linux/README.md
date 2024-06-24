Management Component Transport Protocol (MCTP) using Linux sockets
------------------------------------------------------------------

This crate provides an implementation of the `mctp` base crate, using Linux
socket support for MCTP messsaging.

See [https://codeconstruct.com.au/docs/mctp-on-linux-introduction/] for an
overview on the kernel sockets support.

Using the standard sockets API, we implement the `mctp::Endpoint` trait,
allowing upper layers to implement MCTP applications without needing further
details of the sockets interface.
