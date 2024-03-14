use serde::{Deserialize, Serialize};

/// Scan engine detection
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Detection {
    /// Engine ID
    pub engine: i32,
    /// File name
    pub file_name: String,
    /// Virus signature name
    pub virus: String,
}
