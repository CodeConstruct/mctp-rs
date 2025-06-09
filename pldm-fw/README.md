PLDM for Firmware Update library and utilities
----------------------------------------------

This crate provides a PLDM for Firmware Update ("PLDM type 5") implementation
in Rust, as a library. This uses the common [`mctp` traits](../mctp) crate for
communication, and is intended for use in both embedded and standard
environments.

PLDM type 5 is defined by DMTF DSP0267. This crate supports v1.1.0 and v1.2.0
of that specification.

The `pldm-fw` library provides type definitions and serialisation
implementations for type-5 communication. The `pkg` module provides support for
reading PLDM package files, which can then be used for updates.

The related [`pldm-fw-cli`](../pldm-fw-cli) crate uses this crate to implement a
small firmware update agent (UA) as a Linux command-line utility.
