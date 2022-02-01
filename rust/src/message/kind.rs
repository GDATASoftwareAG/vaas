use serde::{Serialize, Deserialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Kind{
    AuthRequest,
    AuthResponse,
    VerdictRequest,
    VerdictResponse,
    Error,
}