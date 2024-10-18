use std::collections::HashMap;

use futures::{channel::oneshot, lock::Mutex};

use crate::{error::VResult, message::VerdictResponse};

struct VerdictResponses {
    responses: Mutex<HashMap<String, oneshot::Sender<VResult<VerdictResponse>>>>,
}

impl VerdictResponses {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get_response(&self, request_id: &str) -> VResult<VerdictResponse> {
        let mut requests = self.responses.lock().await;
        let (sender, receiver) = oneshot::channel();
        requests.insert(request_id.to_string(), sender);
        receiver.await.expect("Sender has been dropped")
    }

    pub async fn set_response(&self, request_id: &str, response: VResult<VerdictResponse>) {
        let mut requests = self.responses.lock().await;
        if let Some(r) = requests.remove(request_id) {
            r.send(response);
        }
    }

    //   set_all_responses
}
