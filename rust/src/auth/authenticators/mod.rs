//! # Authenticators
//! 
//! This module contains the different **OAuth2 Grant Types** that can be used to authenticate against the VaaS service.

mod client_credentials;
mod password;

pub use client_credentials::ClientCredentials;
pub use password::Password;
