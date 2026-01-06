#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub use_cache: bool,
    pub use_hash_lookup: bool,
}

#[derive(Debug, Clone)]
pub struct ForSha256Options {
    pub use_cache: bool,
    pub use_hash_lookup: bool,
}

impl ForSha256Options {
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

#[derive(Debug, Clone)]
pub struct ForFileOptions {
    pub use_cache: bool,
    pub use_hash_lookup: bool,
}

impl ForFileOptions {
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

#[derive(Debug, Clone)]
pub struct ForStreamOptions {
    pub use_hash_lookup: bool,
}

impl ForStreamOptions {
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

#[derive(Debug, Clone)]
pub struct ForUrlOptions {
    pub use_hash_lookup: bool,
}

impl ForUrlOptions {
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
