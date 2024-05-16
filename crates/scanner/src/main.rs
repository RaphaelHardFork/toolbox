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
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
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

    match cli.subcommand() {
        Some(("scan", args)) => {
            if let Some(target) = args.get_one::<String>("target") {
                scan(target);
            }
        }
        Some(("modules", _)) => {
            let subdomains_modules = modules::subdomains_modules();
            println!("\nSubdomains modules");
            for module in subdomains_modules {
                println!("- {:25}{}", module.name(), module.description());
            }
            let http_modules = modules::http_modules();
            println!("\nHTTP modules");
            for module in http_modules {
                println!("- {:35}{}", module.name(), module.description());
            }
        }

        // fallback (never used: filtered by clap)
        _ => println!("NOTHING"),
    }

    // let scan_start = Instant::now();

    // // enumerate subdomains
    // let subdomains = subdomains::enumerate(&http_client, target).await?;

    // // scan ports for each subdomains
    // let scan_result: Vec<Subdomain> = stream::iter(subdomains.into_iter())
    //     .map(|subdomain| ports::scan_ports(PORTS_CONCURRENCY, subdomain))
    //     .buffer_unordered(SUBDOMAINS_CONCURRENCY)
    //     .collect()
    //     .await;

    // // display result
    // for subdomain in scan_result {
    //     println!("Open ports in {}", &subdomain.domain);
    //     for port in &subdomain.open_ports {
    //         println!("{}", port.port);
    //     }
    // }

    // info!("{:12} - {:?}", "SCAN COMPLETED", scan_start.elapsed());

    Ok(())
}
