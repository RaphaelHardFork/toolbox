use crate::model::Subdomain;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::{sync::Arc, time::Duration};

const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;

pub type DnsResolver = Arc<TokioAsyncResolver>;

pub fn new_resolver() -> DnsResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(RESOLVE_DNS_TIMEOUT_MS);
    let dns_resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

    Arc::new(dns_resolver)
}

pub async fn resolves(dns_resolver: &DnsResolver, domain: Subdomain) -> Option<Subdomain> {
    match dns_resolver.lookup_ip(domain.domain.as_str()).await {
        Ok(_) => Some(domain),
        Err(_) => None,
    }
}
