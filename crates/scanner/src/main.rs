mod dns;
mod error;
mod model;
mod modules;
mod ports;
mod scan;

pub use error::{Error, Result};

use clap::{Arg, Command};
use scan::scan;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, io};
use tracing::instrument::WithSubscriber;
use tracing::{debug, error, info, subscriber};
use tracing_appender::non_blocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::{prelude::*, Registry};

use crate::model::{ensure_dir, export_to_json, export_to_markdown};

// timeouts
pub const SOCKET_CON_TIMEOUT_MS: u64 = 3000;
pub const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;

fn main() -> Result<()> {
    let cli = Command::new(clap::crate_name!())
        .version(clap::crate_version!())
        .subcommand(Command::new("modules").about("List all modules"))
        .subcommand(
            Command::new("scan")
                .about("Scan a target")
                .arg(
                    Arg::new("target")
                        .help("The domain name to scan")
                        .value_name("TARGET")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("logs")
                        .short('s')
                        .long("logs")
                        .num_args(0)
                        .value_name(None)
                        .help("Save logs into a .log file"),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Output format")
                        .value_name("OUTPUT")
                        .value_parser(["json", "md", "both"])
                        .default_value("both"),
                ),
        )
        .arg_required_else_help(true)
        .get_matches();

    match cli.subcommand() {
        Some(("modules", _)) => modules::display_all(),
        Some(("scan", args)) => {
            if let Some(target) = args.get_one::<String>("target") {
                // create filename
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let filename = format!("{}", timestamp);

                // create output dir
                let output_dir = format!("output/scanner/{}", target);
                ensure_dir(output_dir.as_ref())?;

                let save_logs = *args.get_one::<bool>("logs").unwrap_or(&false);
                init_tracing_subscriber(save_logs, output_dir.as_ref(), &filename);

                // run the scanner
                info!("Scanning {} (run_{})", target, timestamp);
                let result = scan(target)?;

                // write result
                if let Some(format) = args.get_one::<String>("output") {
                    if format == "both" || format == "json" {
                        let json_path = Path::new(&output_dir)
                            .join(&filename)
                            .with_extension("json");
                        export_to_json(&result, &json_path)?;
                    }

                    if format == "both" || format == "md" {
                        let md_path = Path::new(&output_dir).join(filename).with_extension("md");
                        export_to_markdown(&result, &target, &md_path)?;
                    }
                }
            }
        }

        // fallback if a cmd is not handled (should not possible)
        _ => {
            error!("{:12} - Command not handled, exit program", "CLI ERROR");
            return Err(Error::CliUsage("Command not handled".into()));
        }
    }

    Ok(())
}

fn init_tracing_subscriber(save_logs_file: bool, output_dir: &Path, filename: &str) {
    // base for the subscriber
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::CLOSE);

    if save_logs_file {
        let filename = format!("{}.log", filename);
        let file_appender = RollingFileAppender::new(Rotation::NEVER, output_dir, filename);
        let suscriber = subscriber
            .with_ansi(false)
            .with_file(false)
            .with_target(false)
            .with_writer(file_appender)
            .finish();

        // add log in terminal as an additional layer
        let stdout_layer = layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(true)
            .with_file(false)
            .with_target(false);

        // init the subscriber
        tracing::subscriber::set_global_default(suscriber.with(stdout_layer))
            .expect("Unable to set global subscriber with 2 layer");
    } else {
        let suscriber = subscriber
            .with_ansi(true)
            .with_file(false)
            .with_target(false)
            .finish();

        // init the subscriber
        tracing::subscriber::set_global_default(suscriber)
            .expect("Unable to set global subscriber with 2 layer");
    }
}
