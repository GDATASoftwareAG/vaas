use serde::Deserialize;
use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Error)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub details: Option<String>,
}

impl Display for ProblemDetails {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} - {} ",
            self.r#type.as_deref().unwrap_or_default(),
            self.details.as_deref().unwrap_or_default()
        )
    }
}
