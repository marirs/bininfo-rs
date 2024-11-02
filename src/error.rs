use authenticode::AttributeCertificateAuthenticodeError;

#[derive(Debug)]
pub enum Error {
    InvalidIdentifier,
    InvalidEndianness,
    UnsupportedFileType,
    IoError(std::io::Error),
    GoblinError(goblin::error::Error),
    ExeError(exe::Error),
    AttributeCertificateAuthenticodeError(AttributeCertificateAuthenticodeError),
    AuthenticodeError(authenticode::AttributeCertificateError),

    /// File does not exist
    FileNotFound,
    /// Null address.
    Null,
    /// Out of bounds.
    ///
    /// Catch-all for bounds check errors.
    Bounds,
    /// Data is not available.
    ///
    /// Can happen when referencing data in `PeFile` instances.
    ///
    /// Sections can be shorter than stored on disk, the remaining bytes will default to zeroes when loaded by the system.
    /// Since these zeroes would just be a waste of space, they are not present in the binaries on disk.
    /// This error happens when attempting to get a reference to such zero filled data.
    ZeroFill,
    /// Data is not available.
    ///
    /// Can happen when referencing data in `PeView` instances.
    ///
    /// Sections can have excess in their raw data which won't be mapped when loaded by the system.
    /// This error happens when attempting to get a reference to such unmapped raw data.
    /// Sometimes this kind of excess is called an overlay.
    Unmapped,
    /// Address is misaligned.
    Misaligned,
    /// Expected magic number does not match.
    BadMagic,
    /// Trying to load a PE32 file with a PE32+ parser or vice versa.
    PeMagic,
    /// Sanity check failed.
    ///
    /// Some value was so far outside its typical range, while not technically incorrect, probably indicating something went wrong.
    /// If this error is encountered legitimately, create an issue or file a PR to relax the artificial restrictions.
    Insanity,
    /// Invalid data.
    ///
    /// Structured data was found which simply isn't valid.
    /// Catch-all for errors which don't fall under other errors.
    Invalid,
    /// Overflow error.
    ///
    /// Catch-all for overflow and underflow errors.
    Overflow,
    /// Encoding error.
    ///
    /// Catch-all for string related errors such as lacking a nul terminator.
    Encoding,
    /// Aliasing error.
    ///
    /// Request cannot be fulfilled because it would alias with an existing borrow.
    Aliasing,
}

// Froms
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<goblin::error::Error> for Error {
    fn from(e: goblin::error::Error) -> Self {
        Error::GoblinError(e)
    }
}

impl From<exe::Error> for Error {
    fn from(e: exe::Error) -> Self {
        Error::ExeError(e)
    }
}

impl From<authenticode::AttributeCertificateAuthenticodeError> for Error {
    fn from(e: authenticode::AttributeCertificateAuthenticodeError) -> Self {
        Error::AttributeCertificateAuthenticodeError(e)
    }
}

impl From<authenticode::AttributeCertificateError> for Error {
    fn from(e: authenticode::AttributeCertificateError) -> Self {
        Error::AuthenticodeError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
