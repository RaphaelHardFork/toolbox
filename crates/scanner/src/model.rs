use crate::{modules::http::HttpFinding, Result};
use serde::Serialize;
use serde_json::to_string_pretty;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

// region:        --- Models

#[derive(Debug, Serialize)]
pub struct Subdomain {
    pub domain: String,
    pub ip: String,
    pub open_ports: Vec<Port>,
}

#[derive(Debug, Serialize)]
pub struct Port {
    pub port: u16,
    pub is_open: bool,
    pub findings: Vec<HttpFinding>,
}

// endregion:     --- Models

// region:        --- Exporting utils

pub fn ensure_dir(dir: &Path) -> Result<bool> {
    if dir.is_dir() {
        Ok(false)
    } else {
        fs::create_dir_all(dir)?;
        Ok(true)
    }
}

pub fn export_to_json(result: &Vec<Subdomain>, path: &Path) -> Result<()> {
    let json = to_string_pretty(result)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub fn export_to_markdown(result: &Vec<Subdomain>, target: &str, path: &Path) -> Result<()> {
    let mut md_content = String::new();
    writeln!(&mut md_content, "# Scan result for `{}`", target)?;
    writeln!(&mut md_content, "")?;
    writeln!(&mut md_content, "*Vulnerabilities are displayed under an open port, if this one is empty it mean no vulnerabilities are found on this open port.*")?;

    for subdomain in result {
        writeln!(&mut md_content, "")?;
        writeln!(
            &mut md_content,
            "## Subdomain {} ({})",
            subdomain.ip, subdomain.domain
        )?;
        if subdomain.open_ports.is_empty() {
            writeln!(&mut md_content, "There is not open ports for this domain")?;
            continue;
        }
        writeln!(&mut md_content, "")?;
        writeln!(&mut md_content, "Open ports:")?;
        writeln!(&mut md_content, "")?;

        for port in &subdomain.open_ports {
            writeln!(&mut md_content, "- Port **{}**", port.port)?;
            for finding in &port.findings {
                writeln!(&mut md_content, "  - {:?}", finding)?;
            }
        }
    }

    let mut file = File::create(path)?;
    file.write_all(md_content.as_bytes())?;
    Ok(())
}

// endregion:     --- Exporting utils
