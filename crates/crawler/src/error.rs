use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    #[from]
    ParseFloat(std::num::ParseFloatError),

    #[from]
    ParseUsize(std::num::ParseIntError),

    #[from]
    SystemTime(std::time::SystemTimeError),

    #[from]
    File(std::io::Error),

    #[from]
    Reqwest(reqwest::Error),

    #[from]
    WebDriver(fantoccini::error::CmdError),
}

// region:    --- Error Boilerplate

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
