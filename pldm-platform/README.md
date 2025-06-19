# PLDM Platform

This crate implements PLDM Platform ("type 2") handling.

Currently only a subset of commands are implemented. 
PLDM type 2 is defined by DMTF DSP0248 and DSP0249 (state sets).

At the moment the crate requires `alloc`, that requirement will be relaxed later.

[`pldm-platform-util`](../pldm-platform-util) crate provides a PLDM 
requester program to run on Linux.




