use std::{collections::HashSet, time::Duration};

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};
use ureq::Agent;

use crate::{
    error::Result,
    model::{CrtShEntry, Subdomain},
    RESOLVE_DNS_TIMEOUT_MS,
};

pub fn enumerate(agent: &Agent, target: &str) -> Result<Vec<Subdomain>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", target);

    println!("Request: {:?}", url);
    let entries: Vec<CrtShEntry> = agent.get(&url).call()?.into_json()?;

    // cleaning entries
    let mut subdomains: HashSet<String> = entries
        .into_iter()
        .flat_map(|entry| {
            entry
                .name_value
                .split('\n')
                .map(|subdomain| subdomain.trim().to_string())
                .collect::<Vec<String>>()
        })
        .filter(|subdomain| subdomain != target)
        .filter(|subdomain| !subdomain.contains('*'))
        .collect();
    subdomains.insert(target.to_string());

    println!("Subdomains to resolves: {:?}", subdomains);

    // only keep resolved subdomains
    let subdomains: Vec<Subdomain> = subdomains
        .into_iter()
        .map(|domain| Subdomain {
            domain,
            open_ports: Vec::new(),
        })
        .filter(resolves)
        .collect();

    Ok(subdomains)
}

pub fn resolves(domain: &Subdomain) -> bool {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(RESOLVE_DNS_TIMEOUT_MS);

    let dns_resolver = Resolver::new(ResolverConfig::default(), opts)
        // panic if the DNS client fail to build
        .expect("subdomains resolver: failed to build DNS client");

    dns_resolver.lookup_ip(domain.domain.as_str()).is_ok()
}
