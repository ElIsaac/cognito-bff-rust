use std::sync::Mutex;

use application::ports::{UpstreamApi, UpstreamError, UpstreamRequest, UpstreamResponse};

use crate::util::lock;

#[derive(Debug)]
struct State {
    requests: Vec<UpstreamRequest>,
    result: Result<UpstreamResponse, UpstreamError>,
}

/// API upstream de mentira: registra lo recibido y responde lo configurado.
#[derive(Debug)]
pub struct FakeUpstream {
    state: Mutex<State>,
}

impl Default for FakeUpstream {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeUpstream {
    /// Por defecto responde `200` con body `ok`.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                requests: Vec::new(),
                result: Ok(UpstreamResponse {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                    body: b"ok".to_vec(),
                }),
            }),
        }
    }

    pub fn respond_with(&self, resp: UpstreamResponse) {
        lock(&self.state).result = Ok(resp);
    }

    pub fn fail_with(&self, err: UpstreamError) {
        lock(&self.state).result = Err(err);
    }

    pub fn requests(&self) -> Vec<UpstreamRequest> {
        lock(&self.state).requests.clone()
    }

    pub fn request_count(&self) -> usize {
        lock(&self.state).requests.len()
    }
}

impl UpstreamApi for FakeUpstream {
    async fn forward(&self, req: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        let mut state = lock(&self.state);
        state.requests.push(req);
        state.result.clone()
    }
}
