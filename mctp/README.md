Management Component Transport Protocol (MCTP) support
------------------------------------------------------

This crate provides a set of generic types and traits for MCTP support in Rust.
It provides:

 * a few base types (`Eid`, `Tag`, `MsgType`) to match MCTP protocol
   definitions,

 * a `MctpEndpoint` trait, to abstract communication implementation details; and

 * some support types (`MctpError`, `Result`) for the `MctpEndpoint` trait.

There are two typical interfaces to the crate:

 * Transport implementations: code that provides implementations of the
   `MctpEndpoint` trait. These interface to hardware (either directly, in
   embedded environments, or through an operating system interface), and
   provide the base message send/receive functions

 * Application implementations: code that uses makes use of the `MctpEndpoint`
   trait, in order to provide some MCTP-based functionality.

API status
----------

While this is fairly early prototype code, there are a couple of uses "in the
field" to help validate the API conventions. While we don't expect much API
breakage in future, there may be reworks coming.

Any API changes will be appropriately versioned.

Future items
------------

 * Some uses may need the type and IC bit to be returned from
   `Endpoint::recv()`, in order to correctly process messages in situations
   where the protocol allows different IC states, or multiple protocols are
   received on one `Endpoint` object. In this case, we may want a richer version
   of `recv`, returning the IC and type values.
