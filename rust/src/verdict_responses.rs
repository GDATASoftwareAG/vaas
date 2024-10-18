use crate::error::VResult;
use futures_util::{TryFutureExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Mutex;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;

#[derive(Debug)]
pub(crate) struct Responses<T: Clone + Debug> {
    responses: Mutex<HashMap<String, Sender<T>>>,
}

impl<T: Clone + Debug> Responses<T> {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_response(&self, request_id: String) -> impl Future<Output = VResult<T>> {
        let receiver = {
            let mut requests = self.responses.lock().unwrap_or_else(|e| e.into_inner());
            let (sender, receiver) = oneshot::channel();
            requests.insert(request_id, sender);
            receiver
        };
        receiver.map_err(|_| crate::error::Error::Cancelled)
    }

    pub fn set_response(&self, request_id: &str, response: T) {
        let mut requests = self.responses.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = requests.remove(request_id) {
            if r.send(response).is_err() {
                // TODO: proper logging
                eprintln!("cannot send");
            }
        } else {
            eprintln!("cannot find request id");
        }
    }

    pub fn set_all_responses(&self, response: T) {
        let senders: Vec<Sender<T>> = {
            let mut responses = self.responses.lock().unwrap_or_else(|e| e.into_inner());
            responses.drain().map(|(_, value)| value).collect()
        };

        for s in senders {
            s.send(response.clone()).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::verdict_responses::Responses;

    const TEST_REQUEST_ID: &str = "1234";

    #[tokio::test]
    pub async fn get_response_returns_verdict_response() {
        let responses = Responses::new();
        let response_future = responses.get_response(TEST_REQUEST_ID.to_string());
        responses.set_response(TEST_REQUEST_ID, 42);
        assert_eq!(response_future.await.unwrap(), 42);
    }

    #[tokio::test]
    pub async fn get_response_if_set_all_returns() {
        let responses = Responses::new();
        let response_future = responses.get_response(TEST_REQUEST_ID.to_string());
        responses.set_all_responses(42);
        assert_eq!(response_future.await.unwrap(), 42);
    }
}
