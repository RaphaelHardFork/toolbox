use derive_more::From;
use std::io;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    CliUsage(String),
    InvalidHttpResponse(String),

    #[from]
    IO(io::Error),

    #[from]
    Write(std::fmt::Error),

    #[from]
    SystemTime(std::time::SystemTimeError),

    #[from]
    Serialize(serde_json::Error),

    #[from]
    Reqwest(reqwest::Error),

    #[from]
    Tokio(tokio::task::JoinError),
}

// region:    --- Error Boilerplate

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
