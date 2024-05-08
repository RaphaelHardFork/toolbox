use error::Result;
use model::Subdomain;
use rayon::prelude::*;
use std::{env, time::Duration};
use ureq::Agent;

mod error;
mod model;
mod ports;
mod subdomains;

// global timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 10000;
pub const SOCKET_CON_TIMEOUT_MS: u64 = 3000;
pub const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;

fn main() -> Result<()> {
    // collect and validate args

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(error::Error::CliUsage(
            "Usage:\ncargo run <domain>".to_string(),
        ));
    }
    let target = args[1].as_str();

    // request crt.sh
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS))
        .build();

    let pool = rayon::ThreadPoolBuilder::new().num_threads(256).build()?;
    let _ = pool.install(|| -> Result<()> {
        let scan_result: Vec<Subdomain> = subdomains::enumerate(&agent, target)?
            .into_par_iter()
            .map(ports::scan_ports)
            .collect();

        for subdomain in scan_result {
            println!("Open ports on subdomain: {}", &subdomain.domain);
            for port in &subdomain.open_ports {
                println!("{}", port.port)
            }
            println!()
        }

        Ok(())
    });

    // will wait for each subdomains and each ports
    // scan_single_threaded(&agent, target)?;

    Ok(())
}

#[allow(dead_code)]
fn scan_single_threaded(agent: &Agent, target: &str) -> Result<()> {
    let scan_result: Vec<Subdomain> = subdomains::enumerate(agent, target)?
        .into_iter()
        .map(ports::scan_ports)
        .collect();

    for subdomain in scan_result {
        println!("Subdomain: {}", &subdomain.domain);
        for port in &subdomain.open_ports {
            println!("{}", port.port)
        }
        println!()
    }

    Ok(())
}
