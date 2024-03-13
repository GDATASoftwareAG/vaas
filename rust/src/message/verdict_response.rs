use super::{Detection, LibMagic};
use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VerdictResponse {
    pub sha256: String,
    pub guid: String,
    pub verdict: String,
    pub url: Option<String>,
    pub upload_token: Option<String>,
    pub detections: Option<Vec<Detection>>,
    pub lib_magic: Option<LibMagic>,
}

impl TryFrom<&String> for VerdictResponse {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::message::{detection::Detection, lib_magic::LibMagic, VerdictResponse};

    #[test]
    fn deserialize() {
        let json = r#"{"sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","file_name":null,"verdict":"Malicious","upload_token":null,"url":null,"detections":[{"engine":2,"file_name":"/tmp/scan/051f699f-b21f-4d33-9cdd-d8b2f01e6118","virus":"EICAR-Test-File"},{"engine":3,"file_name":"/tmp/scan/051f699f-b21f-4d33-9cdd-d8b2f01e6118","virus":"EICAR_TEST_FILE"}],"lib_magic":{"file_type":"EICAR virus test files","mime_type":"text/plain"},"kind":"VerdictResponse","request_id":"ed7207a5-d65a-4400-b91c-673ff39cfd8b","guid":"ed7207a5-d65a-4400-b91c-673ff39cfd8b"}"#;
        let verdict_response: VerdictResponse = serde_json::from_str(json).unwrap();

        assert_eq!(
            VerdictResponse {
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                    .to_string(),
                guid: "ed7207a5-d65a-4400-b91c-673ff39cfd8b".to_string(),
                verdict: "Malicious".to_string(),
                url: None,
                upload_token: None,
                detections: Some(vec![
                    Detection {
                        engine: 2,
                        file_name: "/tmp/scan/051f699f-b21f-4d33-9cdd-d8b2f01e6118".to_string(),
                        virus: "EICAR-Test-File".to_string()
                    },
                    Detection {
                        engine: 3,
                        file_name: "/tmp/scan/051f699f-b21f-4d33-9cdd-d8b2f01e6118".to_string(),
                        virus: "EICAR_TEST_FILE".to_string()
                    }
                ]),
                lib_magic: Some(LibMagic {
                    file_type: "EICAR virus test files".to_string(),
                    mime_type: "text/plain".to_string()
                })
            },
            verdict_response
        );
    }
}
