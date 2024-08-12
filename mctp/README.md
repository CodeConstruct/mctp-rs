Management Component Transport Protocol (MCTP) support
------------------------------------------------------

This crate provides a set of generic types and traits for MCTP support in Rust.
It provides:

 * a few base types (`Eid`, `Tag`, `MsgType`) to match MCTP protocol
   definitions,

 * `Comm` and `Listener` traits, to abstract communication implementation details; and

 * some support types (`MctpError`, `Result`) for the traits.

There are two typical interfaces to the crate:

 * Transport implementations: code that provides implementations of the `Comm`
   and `Listner` traits. These interface to hardware (either directly, in
   embedded environments, or through an operating system interface), and
   provide the base message send/receive functions

 * Application implementations: code that uses makes use of the `Comm` trait,
   in order to provide some MCTP-based functionality.

API status
----------

While this is fairly early prototype code, there are a couple of uses "in the
field" to help validate the API conventions. While we don't expect much API
breakage in future, there may be reworks coming.

Any API changes will be appropriately versioned.

