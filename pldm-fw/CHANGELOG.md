# Changelog

## [0.2.0] - 2025-06-09

### Added

- Added Firmware Device (FD) implementation, works on `no_std`.
- Moved `pldm-fw` binary to a new `pldm-fw-cli` crate.

### Fixed

- Fix incorrect transfer size field on 64-bit platforms.
- UA: support PCI device and subsystem IDs.
- UA: avoid divide by zero in progress on early TransferComplete.

### Changed

- Moved Update Agent (UA) to a separate module.
- Support building with `no_std` (not for UA).
- Update for `mctp` 0.2 API.
- License is now dual MIT or Apache-2.0

## [0.1.0] - 2024-06-24
