use super::{HttpFinding, HttpModule};
use crate::modules::{http_request, Module};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;
use tracing::instrument;

// region:        --- Module info

pub struct GitDirectoryDisclosure {}

impl GitDirectoryDisclosure {
    pub fn new() -> Self {
        Self {}
    }

    fn is_git_directory_listing(&self, content: &str) -> bool {
        content.contains("HEAD")
            && content.contains("refs")
            && content.contains("config")
            && content.contains("index")
            && content.contains("objects")
    }
}

impl Module for GitDirectoryDisclosure {
    fn name(&self) -> String {
        "http/git_directory_disclosure".to_string()
    }
    fn description(&self) -> String {
        "Check if a .git. directory disclosure".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for GitDirectoryDisclosure {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/.git/", &endpoint);
        let res = http_request(&http_client, &url).await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if self.is_git_directory_listing(&body) {
            return Ok(Some(HttpFinding::GitDirectoryDisclosure(url)));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::GitDirectoryDisclosure;

    #[tokio::test]
    async fn is_git_directory() {
        let module = GitDirectoryDisclosure::new();

        let body = r#"COMMIT_EDITMSG
FETCH_HEAD
HEAD
ORIG_HEAD
config
description
hooks
index
info
logs
objects
refs"#;

        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.fr</title> sdsds";

        assert_eq!(true, module.is_git_directory_listing(body));
        assert_eq!(false, module.is_git_directory_listing(body2));
    }
}
