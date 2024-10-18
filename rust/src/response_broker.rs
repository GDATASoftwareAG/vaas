use futures_util::FutureExt;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Mutex;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::RecvError;
use tokio::sync::oneshot::Sender;

#[derive(Debug)]
pub(crate) struct ResponseBroker<T: Clone + Debug, E: From<RecvError> + Clone + std::error::Error> {
    responses: Mutex<HashMap<String, Sender<Result<T, E>>>>,
}

impl<T: Clone + Debug, E: From<RecvError> + Clone + std::error::Error> ResponseBroker<T, E> {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_response(&self, request_id: String) -> impl Future<Output = Result<T, E>> {
        let receiver = {
            let mut requests = self.responses.lock().unwrap_or_else(|e| e.into_inner());
            let (sender, receiver) = oneshot::channel();
            requests.insert(request_id, sender);
            receiver
        };
        receiver.map(|r| r?)
    }

    pub fn set_response(&self, request_id: &str, response: Result<T, E>) {
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

    pub fn set_all_responses(&self, response: Result<T, E>) {
        let senders: Vec<Sender<Result<T, E>>> = {
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
    use crate::response_broker::ResponseBroker;

    const TEST_REQUEST_ID: &str = "1234";

    #[tokio::test]
    pub async fn get_response_returns_verdict_response() {
        let responses: ResponseBroker<i32, crate::error::Error> = ResponseBroker::new();
        let response_future = responses.get_response(TEST_REQUEST_ID.to_string());
        responses.set_response(TEST_REQUEST_ID, Ok(42));
        assert_eq!(response_future.await.unwrap(), 42);
    }

    #[tokio::test]
    pub async fn get_response_if_set_all_returns() {
        let responses: ResponseBroker<i32, crate::error::Error> = ResponseBroker::new();
        let response_future = responses.get_response(TEST_REQUEST_ID.to_string());
        responses.set_all_responses(Ok(42));
        assert_eq!(response_future.await.unwrap(), 42);
    }
}
