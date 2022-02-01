use crate::message::kind::Kind;
use serde::{Serialize, Deserialize};

#[derive(Serialize,Deserialize)]
pub struct ErrorResponse {
    #[serde(alias = "type")]
    pub error_type: String,
    pub text: String,
    pub kind: Kind,
}