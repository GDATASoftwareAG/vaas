use crate::error::VResult;
use futures::channel::oneshot;
use futures_util::{TryFutureExt};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

struct VerdictResponses<T> {
    responses: Mutex<HashMap<String, oneshot::Sender<T>>>,
}

impl<T> VerdictResponses<T> {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_response(&self, request_id: &str) -> impl Future<Output = VResult<T>> {
        let receiver = {
            let mut requests = self.responses.lock().unwrap_or_else(|e| e.into_inner());
            let (sender, receiver) = oneshot::channel();
            requests.insert(request_id.to_string(), sender);
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

    //   set_all_responses
}

#[cfg(test)]
mod tests {
    use crate::verdict_responses::VerdictResponses;

    const TEST_REQUEST_ID: &str = "1234";

    #[tokio::test]
    pub async fn get_response_returns_verdict_response() {
        let responses = VerdictResponses::new();
        let response_future = responses.get_response(TEST_REQUEST_ID);
        responses.set_response(TEST_REQUEST_ID, 42);
        assert_eq!(response_future.await.unwrap(), 42);
    }
}
