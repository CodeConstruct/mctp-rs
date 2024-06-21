// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */


use anyhow::{Context, bail};
use argh::FromArgs;
use enumset::{EnumSet, EnumSetType};
use std::io::Write;
use std::fmt::Write as _;
use mctp_linux::MctpAddr;

fn comma_separated<T: EnumSetType + std::fmt::Debug>(e: EnumSet<T>) -> String {
    let mut s = String::new();
    let mut first = true;
    for i in e.iter() {
        write!(s, "{}{:?}", if first { "" } else { "," }, i).unwrap();
        first = false;
    }
    s
}

fn print_device_info(
    dev: &pldm_fw::DeviceIdentifiers,
    fwp: &pldm_fw::FirmwareParameters,
) {
    println!("Device: {}", dev);
    println!("Firmware Parameters:");
    println!("  Active version:  {}", fwp.active);
    println!("  Pending version: {}", fwp.pending);
    println!(
        "  Update caps: [0x{:x}]:{}",
        fwp.caps.as_u32(),
        if fwp.caps.is_empty() { " none" } else { "" }
    );
    for (cap, is_set) in fwp.caps.values() {
        println!("    * {}", cap.to_desc(is_set));
    }
    println!(
        "  Components:{}",
        if fwp.components.is_empty() { " none" } else { "" }
    );
    for (idx, comp) in fwp.components.iter().enumerate() {
        println!("    [{}]", idx);
        println!("      Classification:  {:?}", comp.classification);
        println!("      Index:           {:?}", comp.classificationindex);
        println!("      Identifier:      0x{:04x}", comp.identifier);
        println!("      Active Version:  {}", comp.active);
        println!("      Pending Version: {}", comp.pending);
        println!(
            "      Activation:      [0x{:x}] {}",
            comp.activation_methods.as_u32(),
            comma_separated(comp.activation_methods)
        );
        println!(
            "      Update caps:     [0x{:x}] {}",
            comp.caps_during_update.as_u32(),
            comma_separated(comp.caps_during_update)
        );
    }
}

fn print_package(pkg: &pldm_fw::pkg::Package) {
    println!("Package:");
    println!("  Identifier:   {}", pkg.identifier);
    println!("  Version:      {}", pkg.version);
    println!("  Applicable devices:");
    for (idx, dev) in pkg.devices.iter().enumerate() {
        println!("   {:2}: {}", idx, dev.ids);
        println!("       version:    {}", dev.version);
        println!("       options:    0x{:x}", dev.option_flags);
        println!("       components: {}", dev.components.as_index_str());
    }
    println!("  Components:");
    for (idx, cmp) in pkg.components.iter().enumerate() {
        println!("   {:2}:", idx);
        println!("       classification: {:?}", cmp.classification);
        println!("       identifier:     0x{:04x}", cmp.identifier);
        println!("       version:        {}", cmp.version);
        println!("       comparison:     0x{:08x}", cmp.comparison_stamp);
        println!("       options:        0x{:04x}", cmp.options);
        println!("       activation:     0x{:04x}", cmp.activation_method);
        println!("       file size:      0x{:04x}", cmp.file_size);
    }
}

fn print_device(dev: &pldm_fw::DeviceIdentifiers) {
    println!("Device: {}", dev);
}

fn print_update(update: &pldm_fw::Update) {
    println!("Update:");
    println!("  Package version: {}", update.package.version);
    println!("  Apply to index:  {}", update.index);
    println!("  Components to update:");
    for (idx, cmp_idx) in update.components.iter().enumerate() {
        let cmp = &update.package.components[*cmp_idx];
        println!("   {:2}: id {:04x}, version {}", idx, cmp.identifier, cmp.version);
    }
}

fn extract_component(pkg: &pldm_fw::pkg::Package, idx: usize) -> anyhow::Result<()> {
    if idx >= pkg.components.len() {
        bail!("no component with index {}", idx);
    }
    let comp = &pkg.components[idx];

    let fname = format!("component-{}.{:04x}.bin", idx, comp.identifier);
    let mut f = std::fs::File::create(&fname)
        .with_context(|| format!("Can't open output file {}", fname))?;

    println!("extracting component {} to {}", idx, fname);

    let mut buf = vec![0u8; comp.file_size];
    pkg.read_component(comp, 0, &mut buf)?;

    f.write(&buf)?;

    Ok(())
}

fn confirm_update() -> bool {
    let mut line = String::new();

    print!("\nConfirm update (y,N)? ");
    let _ = std::io::stdout().flush();
    let rc = std::io::stdin().read_line(&mut line);

    if ! rc.is_ok() {
        return false;
    }

    line.trim().to_ascii_lowercase() == "y"
}

fn open_package(fname: String) -> anyhow::Result<pldm_fw::pkg::Package> {
    let f = std::fs::File::open(&fname)
        .with_context(|| format!("Can't open PLDM package {}", fname))?;

    let pkg = pldm_fw::pkg::Package::parse(f)
        .with_context(|| format!("Can't parse PLDM package {}", fname))?;

    Ok(pkg)
}

#[derive(FromArgs, Debug)]
#[argh(description = "PLDM update utility")]
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Command {
    Inventory(InventoryCommand),
    Update(UpdateCommand),
    Cancel(CancelCommand),
    PkgInfo(PkgInfoCommand),
    Version(VersionCommand),
    Extract(ExtractCommand),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "inventory", description = "Query FD inventory")]
struct InventoryCommand {
    /// MCTP net/EID of device
    #[argh(positional)]
    addr: MctpAddr,
}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "update",
    description = "Update FD from a package file"
)]
struct UpdateCommand {
    /// MCTP EID of device
    #[argh(positional)]
    addr: MctpAddr,

    #[argh(positional)]
    file: String,

    /// provide a specific Component Classification Index (for all components)
    /// during update, defaults to 0.
    #[argh(option)]
    component_index: Option<u8>,

    /// force a specific device from this package (by index)
    #[argh(option)]
    force_device: Option<usize>,

    /// explicitly specify components (by index)
    #[argh(option)]
    force_components: Vec<usize>,

    /// set self-contained activation flag for activate
    #[argh(switch)]
    self_contained_activation: bool,

    /// don't require confirmation to update
    #[argh(switch, short='y')]
    confirm: bool,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "cancel", description = "Cancel ongoing update")]
struct CancelCommand {
    /// MCTP EID of device
    #[argh(positional)]
    addr: MctpAddr,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "pkg-info", description = "Query package contents")]
struct PkgInfoCommand {
    #[argh(positional)]
    file: String,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "extract", description = "Extract package contents")]
struct ExtractCommand {
    #[argh(positional)]
    file: String,

    /// components to extract (by index)
    #[argh(positional)]
    components: Vec<usize>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "version", description = "Print pldm-fw version")]
struct VersionCommand {}

fn duration_str(d: &chrono::Duration) -> String {
    let secs = d.num_seconds();
    if secs < 0 {
        format!("unknown")
    } else if secs > 86400 {
        format!("{} days", secs / 86400)
    } else {
        let mut s = secs;
        let h = s / 3600;
        s -= h * 3600;
        let m = s / 60;
        s -= m * 60;
        format!("{:02}:{:02}:{:02}", h, m, s)
    }
}

fn bps_str(bps: f32) -> String {
    const B_PER_MB : f32 = 1_000_000.0;
    #[allow(non_upper_case_globals)]
    const B_PER_kB : f32 = 1_000.0;
    let threshold = 0.8;

    if bps > (B_PER_MB * threshold) {
        format!("{:.2} MB/sec", bps / B_PER_MB)
    } else if bps > (B_PER_kB * threshold) {
        format!("{:.2} kB/sec", bps / B_PER_kB)
    } else {
        format!("{:.0} B/sec", bps)
    }
}

fn progress(p: &pldm_fw::UpdateTransferProgress)
{
    if p.complete {
        println!(
            "Firmware transfer complete, duration {}, {}",
            duration_str(&p.duration),
            bps_str(p.bps)
        );
    } else {
        let (offset, len) = match p.cur_xfer {
            Some(x) => x,
            None => (0, 0),
        };
        println!(
            "Data request: offset 0x{:08x}, len 0x{:x}, {:2}% {}, {} remaining",
            offset, len, p.percent,
            bps_str(p.bps),
            duration_str(&p.remaining),
        );
    }
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Warn)
        .init();

    match args.command {
        Command::Inventory(i) => {
            let mut ep = i.addr.create_endpoint()?;
            let dev = pldm_fw::query_device_identifiers(&mut ep)?;
            let params = pldm_fw::query_firmware_parameters(&mut ep)?;

            print_device_info(&dev, &params)
        }
        Command::Update(u) => {
            let pkg = open_package(u.file)?;
            let mut ep = u.addr.create_endpoint()?;
            let ep = &mut ep;
            let dev = pldm_fw::query_device_identifiers(ep)?;
            let fwp = pldm_fw::query_firmware_parameters(ep)?;
            let mut update = pldm_fw::Update::new(
                &dev,
                &fwp,
                pkg,
                u.component_index,
                u.force_device,
                u.force_components,
            )?;

            println!("Proposed update:");
            print_device(&dev);
            print_update(&update);

            let c = u.confirm || confirm_update();
            if !c {
                return Ok(())
            }

            let _ = pldm_fw::request_update(ep, &update)?;
            pldm_fw::pass_component_table(ep, &update)?;
            pldm_fw::update_components_progress(ep, &mut update, progress)?;
            pldm_fw::activate_firmware(ep, u.self_contained_activation)?;
        }
        Command::Cancel(c) => {
            let mut ep = c.addr.create_endpoint()?;
            let _ = pldm_fw::cancel_update(&mut ep);
        }
        Command::PkgInfo(p) => {
            let pkg = open_package(p.file)?;
            print_package(&pkg);
        }
        Command::Extract(e) => {
            let pkg = open_package(e.file)?;
            if e.components.len() == 0 {
                println!("No components specified to extract");
            }
            for idx in e.components {
                let res = extract_component(&pkg, idx);
                if let Err(e) = res {
                    println!("Error extracting: {:?}", e);
                }
            }
        }
        Command::Version(_) => {
            println!("pldm-fw version {}", env!("VERSION"));
            return Ok(())
        }
    }

    Ok(())
}
