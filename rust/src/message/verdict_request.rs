use crate::error::VResult;
use serde::Serialize;

pub trait VerdictRequest {
    fn to_json(&self) -> VResult<String>
    where
        Self: Serialize,
    {
        serde_json::to_string(self).map_err(|e| e.into())
    }

    fn guid(&self) -> &str;
}
