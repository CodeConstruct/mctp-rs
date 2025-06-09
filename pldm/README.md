Platform Level Data Model (PLDM) base support
---------------------------------------------

This crate provides some base definitions for the PLDM messaging specification
(DMTF DSP0240).

Communication with remote endpoints is through the MCTP base crate's
`mctp::ReqChannel` and `mctp::Listener` traits.
Platform-specific implementations of traits
are passed to the pldm transfer functions (`pldm_xfer`, `pldm_rx_req`,
`pldm_tx_resp`, `pldm_rx_resp` and `_borrowed` equivalents).
