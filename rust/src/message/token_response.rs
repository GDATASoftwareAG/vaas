use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
}
