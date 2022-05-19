use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Formatter;
use std::ops::Deref;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UploadUrl(pub String);

impl Deref for UploadUrl {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for UploadUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::message::upload_url::UploadUrl;
    use std::ops::Deref;

    #[test]
    fn upload_url_to_string() {
        assert_eq!(
            "https://test.com",
            UploadUrl("https://test.com".to_string()).deref()
        );
    }
}
