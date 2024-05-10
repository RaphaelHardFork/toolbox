use crate::model::{CrtShEntry, Subdomain};
use crate::{Result, RESOLVE_DNS_TIMEOUT_MS};
use futures::{stream, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use std::{collections::HashSet, time::Duration};

type DnsResolver = TokioAsyncResolver;

pub async fn enumerate(http_client: &Client, target: &str) -> Result<Vec<Subdomain>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", target);

    println!("Request: {:?}", url);
    let entries: Vec<CrtShEntry> = http_client.get(url).send().await?.json().await?;

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

    println!("{} subdomains to resolve", subdomains.len());

    // create a DNS resolver
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(RESOLVE_DNS_TIMEOUT_MS);
    let dns_resolver = DnsResolver::tokio(ResolverConfig::default(), opts);

    // using stream to resolve dns
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| Subdomain {
            domain,
            open_ports: Vec::new(),
        })
        .filter_map(|subdomain| {
            let dns_resolver = dns_resolver.clone();
            async move {
                if resolves(&dns_resolver, &subdomain).await {
                    Some(subdomain)
                } else {
                    None
                }
            }
        })
        .collect()
        .await;

    Ok(subdomains)
}

pub async fn resolves(dns_resolver: &DnsResolver, domain: &Subdomain) -> bool {
    dns_resolver.lookup_ip(domain.domain.as_str()).await.is_ok()
}
