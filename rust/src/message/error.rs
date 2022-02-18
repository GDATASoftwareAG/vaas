use crate::message::kind::Kind;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(alias = "type")]
    pub error_type: String,
    pub text: String,
    pub kind: Kind,
}
