use std::fmt::Debug;
use std::ops::Deref;

#[derive(Clone)]
/// Wrapper for a `String`, but does not reveal the string in debug :? formatting
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

impl From<SecretString> for String {
    fn from(s: SecretString) -> Self {
        s.inner
    }
}

#[cfg(test)]
mod tests {
    use crate::authentication::secret_string::SecretString;

    #[test]
    fn secret_string_prints_redacted() {
        let secret: SecretString = "hello".to_string().into();

        let hidden_value = format!("{secret:?}");

        assert_eq!("<redacted>", hidden_value);
    }
}
