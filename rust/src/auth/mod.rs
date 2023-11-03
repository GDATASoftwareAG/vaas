//! # Authentication
//!
//! This module contains all needed funcionality to authenticate against the VaaS service.

mod authenticator;
pub mod authenticators;

pub use authenticator::Authenticator;
