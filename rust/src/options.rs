#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub poll_delay_ms: u64,
    pub keep_alive_delay_ms: u64,
    pub keep_alive: bool,
}
