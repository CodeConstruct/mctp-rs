Platform Level Data Model (PLDM) base support
---------------------------------------------

This crate provides some base definitions for the PLDM messaging specification
(DMTF DSP0240).

Communication with remote endpoints is through the MCTP base crate's
`mctp::Endpoint` trait. Platform-specific implementations of `mctp::Endpoint`
are passed to the pldm transfer functions (`pldm_xfer`, `pldm_rx_req` and
`pldm_tx_resp`).
