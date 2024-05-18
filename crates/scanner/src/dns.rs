use crate::model::Subdomain;
use crate::scan::RESOLVE_DNS_TIMEOUT_MS;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::{sync::Arc, time::Duration};
use tracing::debug;

pub type DnsResolver = Arc<TokioAsyncResolver>;

pub fn new_resolver() -> DnsResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(RESOLVE_DNS_TIMEOUT_MS);
    debug!("DNS resolver options: {:?}", opts);
    let dns_resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

    debug!("DNS resolver created: {:?}", dns_resolver);
    Arc::new(dns_resolver)
}

pub async fn resolves(dns_resolver: &DnsResolver, domain: Subdomain) -> Option<Subdomain> {
    match dns_resolver.lookup_ip(domain.domain.as_str()).await {
        Ok(lookup_ip) => {
            debug!("{:?}", lookup_ip);
            Some(domain)
        }
        Err(err) => {
            debug!("{:?}", err);
            None
        }
    }
}
