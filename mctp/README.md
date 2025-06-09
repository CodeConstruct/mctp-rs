Management Component Transport Protocol (MCTP) support
------------------------------------------------------

This crate provides a set of generic types and traits for MCTP support in Rust.
It provides:

 * A few base types (`Eid`, `Tag`, `MsgType`, `MsgIC`) to match MCTP protocol
   definitions.

 * Traits to abstract communication implementation details. These are
   `ReqChannel`, `Listener`, and `RespChannel`. Async equivalents are
   `AsyncReqChannel`, `AsyncListener`, and `AsyncRespChannel`.

 * Some support types (`mctp::Error`, `mctp::Result`) for the traits.

There are two typical interfaces to the crate:

 * Transport implementations: code that provides implementations of the traits.
   These interface to hardware (either directly, in some
   embedded environments, or through an operating system interface), and
   provide the base message send/receive functions.

 * Application implementations: code that uses makes use of the traits,
   in order to provide some MCTP-based functionality.

API status
----------

We don't expect much API breakage in future, though changes may be made where
it makes sense.

Any API changes will be appropriately versioned.
