use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Kind {
    AuthRequest,
    AuthResponse,
    VerdictRequest,
    VerdictResponse,
    Error,
    VerdictRequestForUrl,
}
