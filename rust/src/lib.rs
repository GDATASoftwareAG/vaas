//! # Verdict-as-a-Service SDK
//!
//! `vaas` is a client SDK for the Verdict-as-a-Service (VaaS) platform by the GDATA CyberSecurity AG.
//! It provides an API to check a hash sum of a file or a file for malicious content.
//!
//! ## Intended For
//!
//! The `vaas` SDK is intended for developers who want to integrate Verdict-as-a-Service into their product.
//! For example to check all files uploaded by user on a website or plugin into an e-mail client, to check all attachments of an e-mail for malicious content.
//!
//! ## Contact
//!
//! For questions and support please contact us at [OEM at GDATA](mailto:oem@gdata.de)!
//!
//! # Examples
//!
//! Check a file hash for malicious content:
//! ```rust,no_run
//! use vaas::{error::VResult, CancellationToken, Vaas, VaasVerdict, Sha256};
//! use vaas::authentication::ClientCredentials;
//! use vaas::options::ForSha256Options;
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> VResult<()> {
//!     let ct = CancellationToken::new();
//!     // Create VaaS instance
//!     let authenticator = ClientCredentials::try_new("client_id".to_string(), "client_secret".to_string())?;
//!     let vaas = Vaas::builder(authenticator).build()?;
//!
//!     // Create the SHA256 we want to check.
//!     let sha256 = Sha256::try_from("698CDA840A0B344639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")?;
//!
//!     // Perform the lookup
//!     let verdict = vaas.for_sha256(&sha256, ForSha256Options::default(), &ct).await?;
//!
//!     // Prints "Clean", "Malicious" or "Unknown"
//!     println!("{}", verdict.verdict);
//!     Ok(())
//! }
//! ```
//!
//! Check a file for malicious content:
//! ```rust,no_run
//! use vaas::{error::VResult, CancellationToken, Vaas, VaasVerdict};
//! use vaas::authentication::ClientCredentials;
//! use vaas::options::ForFileOptions;
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> VResult<()> {
//!     let ct = CancellationToken::new();
//!     // Create VaaS instance
//!     let authenticator = ClientCredentials::try_new("client_id".to_string(), "client_secret".to_string())?;
//!     let vaas = Vaas::builder(authenticator).build()?;
//!
//!     // Create file we want to check.
//!     let file = std::path::Path::new("myfile");
//!
//!     // Perform the lookup
//!     let verdict = vaas.for_file(&file, ForFileOptions::default(), &ct).await?;
//!
//!     // Prints "Clean", "Pup" or "Malicious"
//!     println!("{}", verdict.verdict);
//!     Ok(())
//! }
//! ```
//!
//! Check a file behind a URL for malicious content:
//! ```rust,no_run
//! use vaas::{error::VResult, CancellationToken, Vaas, VaasVerdict};
//! use vaas::authentication::ClientCredentials;
//! use vaas::options::ForUrlOptions;
//! use reqwest::Url;
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> VResult<()> {
//!     let ct = CancellationToken::new();
//!     // Create VaaS instance
//!     let authenticator = ClientCredentials::try_new("client_id".to_string(), "client_secret".to_string())?;
//!     let vaas = Vaas::builder(authenticator).build()?;
//!
//!     let url = Url::parse("https://mytesturl.test").unwrap();
//!
//!     // Perform the lookup
//!     let verdict = vaas.for_url(&url, ForUrlOptions::default(), &ct).await?;
//!
//!     // Prints "Clean", "Pup" or "Malicious"
//!     println!("{}", verdict.verdict);
//!     Ok(())
//! }
//! ```
//!
#![warn(missing_docs)]

pub mod authentication;
pub mod builder;
pub mod error;
mod http;
pub mod message;
pub mod options;
pub mod sha256;
pub mod vaas;
pub mod vaas_verdict;

pub use crate::vaas::Vaas;
pub use builder::Builder;
pub use sha256::Sha256;
pub use vaas_verdict::VaasVerdict;

pub use tokio_util::bytes::Bytes;
pub use tokio_util::sync::CancellationToken;
