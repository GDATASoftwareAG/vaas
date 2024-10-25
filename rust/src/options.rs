#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub keep_alive_delay_ms: u64,
    pub keep_alive: bool,
    pub use_cache: bool,
    pub use_hash_lookup: bool,
}
