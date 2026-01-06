//! Contains configuration options to customize the behavior of VaaS scanning

/// Configuration options applicable when looking up a SHA256 hash
#[derive(Debug, Clone)]
pub struct ForSha256Options {
    /// Whether to allow a cached response instead of a fresh analysis
    pub use_cache: bool,
    /// Whether to perform a cloud hash lookup (for on-prem hosted VaaS)
    pub use_hash_lookup: bool,
}

impl ForSha256Options {
    /// New options with recommended defaults
    pub fn new() -> Self {
        Self {
            use_cache: true,
            use_hash_lookup: true,
        }
    }
}

impl Default for ForSha256Options {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ForFileOptions> for ForSha256Options {
    fn from(options: ForFileOptions) -> Self {
        Self {
            use_cache: options.use_cache,
            use_hash_lookup: options.use_hash_lookup,
        }
    }
}

impl From<ForStreamOptions> for ForSha256Options {
    fn from(options: ForStreamOptions) -> Self {
        Self {
            use_hash_lookup: options.use_hash_lookup,
            ..Default::default()
        }
    }
}

/// Configuration options applicable when looking up a file
#[derive(Debug, Clone)]
pub struct ForFileOptions {
    /// Whether to allow a cached response instead of a fresh analysis
    pub use_cache: bool,
    /// Whether to perform a cloud hash lookup (for on-prem hosted VaaS)
    pub use_hash_lookup: bool,
}

impl ForFileOptions {
    /// New options with recommended defaults
    pub fn new() -> Self {
        Self {
            use_cache: true,
            use_hash_lookup: true,
        }
    }
}

impl Default for ForFileOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ForSha256Options> for ForFileOptions {
    fn from(options: ForSha256Options) -> Self {
        Self {
            use_cache: options.use_cache,
            use_hash_lookup: options.use_hash_lookup,
        }
    }
}

/// Configuration options applicable when looking up a streamed resource
#[derive(Debug, Clone)]
pub struct ForStreamOptions {
    /// Whether to perform a cloud hash lookup (for on-prem hosted VaaS)
    pub use_hash_lookup: bool,
}

impl ForStreamOptions {
    /// New options with recommended defaults
    pub fn new() -> Self {
        Self {
            use_hash_lookup: true,
        }
    }
}

impl Default for ForStreamOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ForSha256Options> for ForStreamOptions {
    fn from(options: ForSha256Options) -> Self {
        Self {
            use_hash_lookup: options.use_hash_lookup,
        }
    }
}

impl From<ForFileOptions> for ForStreamOptions {
    fn from(options: ForFileOptions) -> Self {
        Self {
            use_hash_lookup: options.use_hash_lookup,
        }
    }
}

/// Configuration options applicable when looking up a URL
#[derive(Debug, Clone)]
pub struct ForUrlOptions {
    /// Whether to perform a cloud hash lookup (for on-prem hosted VaaS)
    pub use_hash_lookup: bool,
}

impl ForUrlOptions {
    /// New options with recommended defaults
    pub fn new() -> Self {
        Self {
            use_hash_lookup: true,
        }
    }
}

impl Default for ForUrlOptions {
    fn default() -> Self {
        Self::new()
    }
}
