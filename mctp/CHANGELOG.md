# Changelog

## [0.2.0] - 2025-06-09

### Added

- Traits for `Listener`, `ReqChannel`, `RespChannel` replace
  previous `Endpoint` trait.
- New `AsyncListener`, `AsyncReqChannel, `AsyncRespChannel` traits.
- Optional `defmt` feature.

### Fixed

- Fix `no_std` build.

### Changed

- Added new error variants `NoSpace`, `Unsupported`, 
  `InternalError`, `RxFailure`
- `Tag::OwnedAuto` has been removed, an `Option` is used instead.
- License is now dual MIT or Apache-2.0

## [0.1.0] - 2024-06-24
