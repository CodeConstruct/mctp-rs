PLDM for Firmware Update library and utilities
----------------------------------------------

This crate provides a PLDM for Firmware Update ("PLDM type 5") implementation
in Rust, both as a library and a small command-line utility.

PLDM type 5 is defined by DMTF DSP0267. This crate supports v1.1.0 and v1.2.0
of that specification.

The library
-----------

The `pldm-fw` library provides type definitions and serialisation
implementations for type-5 communication. The `pkg` module provides support for
reading PLDM package files, which can then be used for updates

The `pldm-fw` utility
---------------------

The `pldm-fw` utility uses the library to implement a fairly basic firmware
updater. `pldm-fw` provides a few subcommands for querying a device's firmware
inventory, printing the contents of an update package, and applying an
update package to a device.

```
$ pldm-fw --help
Usage: pldm-fw <command> [<args>]

PLDM update utility

Options:
  --help            display usage information

Commands:
  inventory         Query FD inventory
  update            Update FD from a package file
  cancel            Cancel ongoing update
  pkg-info          Query package contents
  version           Print pldm-fw version
  extract           Extract package contents
```


