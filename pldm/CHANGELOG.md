# Changelog

## [0.2.0] - 2025-06-09

### Added

- Allow no-alloc/`no_std` use of `PldmRequest` and `PldmResponse`.
  `_borrowed()` methods can be used to borrow from
  an external buffer. With `alloc` feature a heap buffer can be
  used the same as previously, returning a `'static` lifetime.
- Add PLDM completion codes.

### Changed

- Update for `mctp` 0.2 API.
- Check that received messages have PLDM message type.
- License is now dual MIT or Apache-2.0

## [0.1.0] - 2024-06-24
