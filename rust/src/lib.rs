//! # Verdict-as-a-Service SDK
//!
//! `vaas` is a client SDK for the Verdict-as-a-Service (VaaS) platform by the GDATA CyberSecurity AG.
//! It provides an API to check a hash sum of a file or a file for malicous content.
//!
//! ## Intended For
//!
//! The `vaas` SDK is intended for developers who want to integrate Verdict-as-a-Service into their product.
//! For example to check all files uploaded by user on a website or plugin into an e-mail client, to check all attachments of an e-mail for malicious content.
//!
//! ## Contact
//!
//! For questions and support please contact us at [OpenSource at GDATA](mailto:opensource@gdata.de)!
//!
//! # Examples
//!
//! Check a file hash for malicious content:
//! ```rust,no_run
//! use vaas::{ Vaas, Sha256, CancellationToken };
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> vaas::error::VResult<()> {
//!     // Cancel the request after 10 seconds if no response is received.
//!     let ct = CancellationToken::from_seconds(10);
//!
//!     // Create the SHA256 we want to check.
//!     let sha256 = Sha256::try_from("698CDA840A0B344639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")?;
//!     
//!     // Create a VaaS instance and request a verdict for the SHA256.
//!     let mut vaas = Vaas::builder(String::from("token"))
//!         .build()?
//!         .connect().await?;
//!
//!     let response = vaas.for_sha256(&sha256, &ct).await?;
//!
//!     // Prints "Clean", "Malicious" or "Unknown"
//!     println!("{}", response.verdict);
//!     Ok(())
//! }
//! ```
//!
//! Check a file for malicious content:
//! ```rust,no_run
//! use vaas::{ Vaas, Sha256, CancellationToken };
//! use std::convert::TryFrom;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> vaas::error::VResult<()> {
//!     // Cancel the request after 10 seconds if no response is received.
//!     let ct = CancellationToken::from_seconds(10);
//!
//!     // Create the SHA256 we want to check.
//!     let file = std::path::PathBuf::from("myfile");
//!     
//!     // Create a VaaS instance and request a verdict for the SHA256.
//!     let mut vaas = Vaas::builder(String::from("token"))
//!         .build()?
//!         .connect().await?;
//!
//!     let response = vaas.for_file(&file, &ct).await?;
//!
//!     // Prints "Clean" or "Malicious"
//!     println!("{}", response.verdict);
//!     Ok(())
//! }
#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

mod builder;
mod cancellation;
mod connection;
pub mod error;
pub mod message;
mod options;
mod sha256;
mod vaas;
mod vaas_verdict;

pub use crate::vaas::Vaas;
pub use builder::Builder;
pub use cancellation::CancellationToken;
pub use cancellation::*;
pub use connection::Connection;
pub use sha256::Sha256;
