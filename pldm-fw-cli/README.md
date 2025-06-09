PLDM for Firmware Update command-line Update Agent
--------------------------------------------------

This crate contains the `pldm-fw` command-line utility: a PLDM for Firmware
Update ("PLDM type 5") Update Agent (UA). This can be used to interact with
devices that implement the PLDM type 5 for their firmware management functions
("firmware devices", or FD), and PLDM firmware package files.

This utility is a small wrapper around the [`pldm-fw`](../pldm-fw) crate, which
implements the actual update and package-handling logic.

Usage
=====

`pldm-fw` has a subcommand-style interface, to invoke one of the query or
update functions of the utility.

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

Each command provides its own usage information. For example, for the
`inventory` command:

```
$ pldm-fw inventory --help
Usage: pldm-fw inventory <addr>

Query FD inventory

Positional Arguments:
  addr              MCTP net/EID of device

Options:
  --help            display usage information
```

Operations that interact with a FD (`inventory`, `update` and `cancel`) will
require an argument that specifies the MCTP address of the device; this is in
`<net>,<eid>` format, representing the MCTP network ID, and MCTP endpoint ID.
The `<net>,` portion is optional; if not specified, the system default network
will be used.
