mod dns;
mod error;
mod model;
mod modules;
mod ports;
mod scan;

pub use error::{Error, Result};

use clap::{Arg, Command};
use futures::{stream, StreamExt};
use model::Subdomain;
use reqwest::Client;
use scan::scan;
use std::env;
use std::time::{Duration, Instant};
use tracing::{debug, error, info};
use tracing_subscriber::fmt::format::{FmtSpan, Format};
use tracing_subscriber::EnvFilter;

// timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 10000;
pub const SOCKET_CON_TIMEOUT_MS: u64 = 3000;
pub const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;

// concurrencies values
const PORTS_CONCURRENCY: usize = 200;
const SUBDOMAINS_CONCURRENCY: usize = 100;

fn main() -> Result<()> {
    // setup tracing
    tracing_subscriber::fmt()
        // .without_time() // DEV
        .with_max_level(tracing::Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .with_env_filter(EnvFilter::from_default_env())
        // .fmt_fields(Format::default().compact())
        .with_target(false)
        .init();

    let cli = Command::new(clap::crate_name!())
        .version(clap::crate_version!())
        .subcommand(Command::new("modules").about("List all modules"))
        .subcommand(
            Command::new("scan").about("Scan a target").arg(
                Arg::new("target")
                    .help("The domain name to scan")
                    .required(true)
                    .index(1),
            ),
        )
        .arg_required_else_help(true)
        .get_matches();

    debug!("Scanner started with: {:?}", cli);
    match cli.subcommand() {
        Some(("scan", args)) => {
            if let Some(target) = args.get_one::<String>("target") {
                scan(target);
            }
        }

        Some(("modules", _)) => modules::display_all(),

        // fallback if a cmd is not handled (should not possible)
        _ => {
            error!("{:12} - Command not handled, exit program", "CLI ERROR");
            return Err(Error::CliUsage("Command not handled".into()));
        }
    }

    Ok(())
}
