use super::{HttpFinding, HttpModule};
use crate::{
    modules::{http_request, Module},
    Result,
};
use async_trait::async_trait;
use reqwest::Client;
use tracing::{info, instrument};

// region:        --- Module info

pub struct DsStoreDisclosure {}

impl DsStoreDisclosure {
    pub fn new() -> Self {
        Self {}
    }

    pub fn is_ds_store_file(&self, content: &[u8]) -> bool {
        match content {
            x if x.len() < 8 => false,
            x => {
                let signature = [0x0, 0x0, 0x0, 0x1, 0x42, 0x75, 0x64, 0x31];
                x[0..8] == signature
            }
        }
    }
}

impl Module for DsStoreDisclosure {
    fn name(&self) -> String {
        "http/ds_store".to_string()
    }
    fn description(&self) -> String {
        "Check if a .DS_Store file disclosure".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for DsStoreDisclosure {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/.DS_Store", &endpoint);
        let res = http_request(&http_client, endpoint).await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.bytes().await?;
        if self.is_ds_store_file(&body.as_ref()) {
            return Ok(Some(HttpFinding::DsStoreDisclosure(url)));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_ds_store() {
        let module = super::DsStoreDisclosure::new();
        let body = "testtesttest";
        let body2 = [
            0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x08, 0x0,
        ];

        assert_eq!(false, module.is_ds_store_file(body.as_bytes()));
        assert_eq!(true, module.is_ds_store_file(&body2));
    }
}
