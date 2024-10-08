//! Implements a SHA256 structure that guarantees that a given hash string is in the correct format.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::{convert::TryFrom, fmt, ops::Deref};

/// Represents a SHA256 hash in its hexadecimal string form.
///
/// # Examples
/// ```rust
/// # fn main() -> vaas::error::VResult<()> {
/// use std::convert::TryFrom;
/// use vaas::Sha256;
///
/// let sha256 = Sha256::try_from("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C")?;
/// # Ok(()) }
/// ```

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Sha256(String);

impl From<&[u8]> for Sha256 {
    fn from(value: &[u8]) -> Self {
        use sha2::Digest;
        use std::fmt::Write;

        let mut hasher = sha2::Sha256::new();
        hasher.update(value);
        let result = hasher.finalize();

        let hex_string = result.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        });
        Self(hex_string)
    }
}

impl TryFrom<&str> for Sha256 {
    type Error = crate::error::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.to_lowercase();
        let re = Regex::new(r"^[A-Fa-f0-9]{64}$").unwrap();

        if re.is_match(&value) {
            Ok(Self(value.to_lowercase()))
        } else {
            Err(Self::Error::InvalidSha256(value))
        }
    }
}

impl Deref for Sha256 {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&PathBuf> for Sha256 {
    type Error = crate::error::Error;

    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        let bytes = std::fs::read(value)?;
        Ok(Self::from(bytes.as_slice()))
    }
}

impl TryFrom<&Path> for Sha256 {
    type Error = crate::error::Error;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::try_from(&value.to_path_buf())
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_valid_sha256() {
        assert_eq!(
            "00015b14c28c2951f6d628098ce6853e14300f1b7d6d985e18d508f9807f44d8",
            Sha256::try_from("00015b14c28c2951f6d628098ce6853e14300f1b7d6d985e18d508f9807f44d8")
                .unwrap()
                .deref()
        );

        assert_eq!(
            "000020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0",
            Sha256::try_from("000020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0")
                .unwrap()
                .deref()
        );
    }

    #[test]
    fn try_from_invalid_sha256() {
        // Wrong characters
        assert!(Sha256::try_from(
            "x00020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0"
        )
        .is_err());

        // Too short
        assert!(Sha256::try_from(
            "00020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0"
        )
        .is_err());

        // Too long
        assert!(Sha256::try_from(
            "1000020f89134d831f48541b2d8ec39397bc99fccf4cc86a3861257dbe6d819d0"
        )
        .is_err());
    }
}
