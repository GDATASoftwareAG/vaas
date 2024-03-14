use serde::{Deserialize, Serialize};

/// File and mime type as classified by https://www.darwinsys.com/file/
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LibMagic {
    /// The file type
    pub file_type: String,
    /// The mime type
    pub mime_type: String,
}
