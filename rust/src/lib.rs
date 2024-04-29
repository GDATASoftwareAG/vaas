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
//! use vaas::auth::authenticators::ClientCredentials;
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> VResult<()> {
//!     // Cancel the request after 10 seconds if no response is received.
//!     let ct = CancellationToken::from_seconds(10);
//!     
//!     //Authenticate and create VaaS instance
//!     let authenticator = ClientCredentials::new("client_id".to_string(), "client_secret".to_string());
//!     let vaas = Vaas::builder(authenticator).build()?.connect().await?;
//!
//!     // Create the SHA256 we want to check.
//!     let sha256 = Sha256::try_from("698CDA840A0B344639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")?;
//!
//!     let verdict = vaas.for_sha256(&sha256, &ct).await?;
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
//! use vaas::auth::authenticators::ClientCredentials;
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> VResult<()> {
//!     // Cancel the request after 10 seconds if no response is received.
//!     let ct = CancellationToken::from_seconds(10);
//!
//!     //Authenticate and create VaaS instance
//!     let authenticator = ClientCredentials::new("client_id".to_string(), "client_secret".to_string());
//!     let vaas = Vaas::builder(authenticator).build()?.connect().await?;
//!
//!     // Create file we want to check.
//!     let file = std::path::PathBuf::from("myfile");
//!
//!     let verdict = vaas.for_file(&file, &ct).await?;
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
//! use vaas::auth::authenticators::ClientCredentials;
//! use reqwest::Url;
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> VResult<()> {
//!     // Cancel the request after 10 seconds if no response is received.
//!     let ct = CancellationToken::from_seconds(10);
//!     
//!     //Authenticate and create VaaS instance
//!     let authenticator = ClientCredentials::new("client_id".to_string(), "client_secret".to_string());
//!     let vaas = Vaas::builder(authenticator).build()?.connect().await?;
//!
//!     let url = Url::parse("https://mytesturl.test").unwrap();
//!     let verdict = vaas.for_url(&url, &ct).await?;
//!
//!     // Prints "Clean", "Pup" or "Malicious"
//!     println!("{}", verdict.verdict);
//!     Ok(())
//! }
//! ```
//!
#![warn(missing_docs)]

pub mod auth;
pub mod builder;
pub mod cancellation;
pub mod connection;
pub mod error;
pub mod message;
mod options;
pub mod sha256;
pub mod vaas;
pub mod vaas_verdict;

pub use crate::vaas::Vaas;
pub use builder::Builder;
pub use cancellation::CancellationToken;
pub use connection::Connection;
pub use sha256::Sha256;
pub use vaas_verdict::VaasVerdict;
