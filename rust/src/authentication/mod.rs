//! # Authentication
//!
//! This module contains all needed funcionality to authenticate against the VaaS service.

mod authenticator;
mod client_credentials;
mod password;
mod secret_string;
mod token_receiver;

pub use authenticator::Authenticator;
pub use client_credentials::ClientCredentials;
pub use password::Password;
