// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM platform utility.
 *
 * Copyright (c) 2025 Code Construct
 */
#[allow(unused)]
use log::{debug, error, info, trace, warn};

use anyhow::{bail, Result};

use argh::FromArgs;
use mctp_linux::MctpAddr;

use pldm_platform::proto::{SensorId, SetSensorOperationalState};

#[derive(FromArgs, Debug)]
#[argh(description = "PLDM platform requester")]
struct Args {
    #[argh(switch, short = 'd')]
    /// debug logging
    debug: bool,

    #[argh(switch)]
    /// trace logging
    trace: bool,

    /// MCTP net/EID of device
    #[argh(positional)]
    addr: MctpAddr,

    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Command {
    NumericSensor(NumericSensorCommand),
    StateSensor(StateSensorCommand),
    NumericEnable(NumericEnableCommand),
    StateEnable(StateEnableCommand),
    Version(VersionCommand),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "version", description = "Print version")]
struct VersionCommand {}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "numeric-sensor",
    description = "Get Numeric Sensor Reading"
)]
struct NumericSensorCommand {
    /// sensor ID
    #[argh(positional)]
    sensor: SensorId,
}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "state-sensor",
    description = "Get State Sensor Reading. Only simple sensors supported."
)]
struct StateSensorCommand {
    /// sensor ID
    #[argh(positional)]
    sensor: SensorId,

    /// state set
    #[argh(option)]
    state_set: Option<u16>,
}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "numeric-enable",
    description = "Set Numeric Sensor Enable"
)]
struct NumericEnableCommand {
    /// event enable. disable, enable, op-only, state-only
    #[argh(option)]
    event: Option<String>,

    /// sensor ID
    #[argh(positional)]
    sensor: SensorId,

    /// operational state. enable, disable, unavailable
    // TODO: could use enums once newer argh is released
    #[argh(positional)]
    op_state: String,
}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "state-enable",
    description = "Set State Sensor Enable. Only simple sensors supported."
)]
struct StateEnableCommand {
    /// event enable. disable, enable, op-only, state-only
    #[argh(option)]
    event: Option<String>,

    /// sensor ID
    #[argh(positional)]
    sensor: SensorId,

    /// operational state. enable, disable, unavailable
    // TODO: could use enums once newer argh is released
    #[argh(positional)]
    op_state: String,
}

fn enable_command_op(op_state: &str) -> Result<SetSensorOperationalState> {
    Ok(if op_state.starts_with("en") {
        SetSensorOperationalState::Enabled
    } else if op_state.starts_with("dis") {
        SetSensorOperationalState::Disabled
    } else if op_state.starts_with("un") {
        SetSensorOperationalState::Unavailable
    } else {
        bail!("Bad operational state '{}'", op_state);
    })
}

fn enable_command_op_event_enable(event: &Option<String>) -> Result<bool> {
    Ok(if let Some(e) = event {
        if e.starts_with("en") || e == "op-only" {
            true
        } else if e.starts_with("dis") || e == "state-only" {
            false
        } else {
            bail!("Bad --event argument");
        }
    } else {
        false
    })
}

fn enable_command_state_event_enable(event: &Option<String>) -> Result<bool> {
    Ok(if let Some(e) = event {
        if e.starts_with("en") || e == "state-only" {
            true
        } else if e.starts_with("dis") || e == "op-only" {
            false
        } else {
            bail!("Bad --event argument");
        }
    } else {
        false
    })
}

fn main() -> anyhow::Result<()> {
    smol::block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    let level = if args.trace {
        log::LevelFilter::Trace
    } else if args.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp(None)
        .init();

    match args.command {
        Command::Version(_) => info!("pldm-platform {}", env!("VERSION")),
        Command::NumericSensor(s) => {
            let mut ep = args.addr.create_req_async()?;
            let reading = pldm_platform::requester::get_sensor_reading(
                &mut ep, s.sensor, false,
            )
            .await?;
            println!("Sensor {} {:?}", s.sensor.0, reading);
        }
        Command::StateSensor(s) => {
            let mut ep = args.addr.create_req_async()?;
            let reading =
                pldm_platform::requester::get_simple_state_sensor_reading(
                    &mut ep, s.sensor, false,
                )
                .await?;
            if let Some(state_set) = s.state_set {
                println!(
                    "Sensor {} {:?}",
                    s.sensor.0,
                    reading.debug_state_set(state_set)
                );
            } else {
                println!("Sensor {} {:?}", s.sensor.0, reading);
            }
        }
        Command::NumericEnable(s) => {
            let mut ep = args.addr.create_req_async()?;
            pldm_platform::requester::set_numeric_sensor_enable(
                &mut ep,
                s.sensor,
                enable_command_op(&s.op_state)?,
                s.event.is_none(),
                enable_command_op_event_enable(&s.event)?,
                enable_command_state_event_enable(&s.event)?,
            )
            .await?;
        }
        Command::StateEnable(s) => {
            let mut ep = args.addr.create_req_async()?;
            pldm_platform::requester::set_simple_state_sensor_enables(
                &mut ep,
                s.sensor,
                enable_command_op(&s.op_state)?,
                s.event.is_none(),
                enable_command_op_event_enable(&s.event)?,
                enable_command_state_event_enable(&s.event)?,
            )
            .await?;
        }
    }
    Ok(())
}
