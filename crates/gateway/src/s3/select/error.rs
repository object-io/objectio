//! Errors of S3 Select, named with AWS's codes.
//!
//! A request refused before the response starts is an S3 XML error (400,
//! or 500 for `InternalError`); one raised while records stream is an error
//! event in the stream, carrying the same code and message.

use std::fmt;

/// An S3 Select failure: an AWS error code and a message for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectError {
    pub code: &'static str,
    pub message: String,
}

impl SelectError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Whether this is the server's fault rather than the request's.
    pub fn is_internal(&self) -> bool {
        self.code == "InternalError"
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("InternalError", message)
    }

    /// The client went away: the response's receiver was dropped. Never
    /// sent to anyone; it only stops the scan.
    pub fn cancelled() -> Self {
        Self::new("Cancelled", "the client closed the connection")
    }

    pub fn is_cancelled(&self) -> bool {
        self.code == "Cancelled"
    }
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SelectError {}

/// Carries a [`SelectError`] through `std::io::Read`, so a failed object
/// read inside a decompressor or a parser comes out with its own code.
pub fn to_io(e: SelectError) -> std::io::Error {
    std::io::Error::other(e)
}

/// The [`SelectError`] inside an I/O error, or `fallback` (a parsing error of
/// the input's format) when the I/O error is the data's fault.
pub fn from_io(e: std::io::Error, fallback: &'static str) -> SelectError {
    if e.get_ref().is_some_and(|inner| inner.is::<SelectError>()) {
        if let Ok(inner) = e.into_inner().unwrap().downcast::<SelectError>() {
            return *inner;
        }
        return SelectError::internal("an object read failed");
    }
    SelectError::new(fallback, e.to_string())
}

pub type SelectResult<T> = Result<T, SelectError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_survives_a_trip_through_io() {
        let e = SelectError::new("OverMaxRecordSize", "too long");
        assert_eq!(from_io(to_io(e.clone()), "CSVParsingError"), e);
    }

    #[test]
    fn a_plain_io_error_takes_the_format_s_code() {
        let e = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad gzip header");
        assert_eq!(
            from_io(e, "InvalidCompressionFormat").code,
            "InvalidCompressionFormat"
        );
    }
}
