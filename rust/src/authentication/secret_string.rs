use std::fmt::Debug;
use std::ops::Deref;

#[derive(Clone)]
/// Wrapper for a `String`, but does not reveal the string in `debug!`
pub struct SecretString {
    inner: String,
}

impl Deref for SecretString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<redacted>")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        SecretString { inner: s }
    }
}
