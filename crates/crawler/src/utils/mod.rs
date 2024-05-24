pub mod log;

use crate::Result;
use std::{fs, path::Path};

pub fn ensure_dir(dir: &Path) -> Result<bool> {
    if dir.is_dir() {
        Ok(false)
    } else {
        fs::create_dir_all(dir)?;
        Ok(true)
    }
}
