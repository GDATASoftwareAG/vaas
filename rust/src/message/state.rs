use crate::message::{VerdictRequest, VerdictResponse};

pub enum State {
    Send(VerdictRequest),
    Received(VerdictResponse),
}
