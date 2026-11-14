//! Cancellation belongs to a client request, never to unrelated durable work.
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const MAX_CLIENTS: usize = 8;
pub const MAX_CLIENT_REQUESTS: usize = 128;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AdmissionError {
    #[error("request capacity reached")]
    Busy,
    #[error("request identifier is already active")]
    Duplicate,
}

pub struct Requests {
    session: CancellationToken,
    active: HashMap<Uuid, CancellationToken>,
    subscription: Option<CancellationToken>,
}

impl Requests {
    pub fn new(session: CancellationToken) -> Self {
        Self { session, active: HashMap::with_capacity(MAX_CLIENT_REQUESTS), subscription: None }
    }
    pub fn admit(&mut self, id: Uuid) -> Result<CancellationToken, AdmissionError> {
        if self.active.contains_key(&id) { return Err(AdmissionError::Duplicate); }
        if self.active.len() == MAX_CLIENT_REQUESTS { return Err(AdmissionError::Busy); }
        let cancellation = self.session.child_token();
        self.active.insert(id, cancellation.clone());
        Ok(cancellation)
    }
    pub fn cancel(&self, id: Uuid) -> bool {
        if let Some(cancellation) = self.active.get(&id) {
            cancellation.cancel();
            true
        } else { false }
    }
    pub fn complete(&mut self, id: Uuid) { self.active.remove(&id); }
    pub fn is_active(&self, id: Uuid) -> bool { self.active.contains_key(&id) }
    pub fn replace_subscription(&mut self) -> CancellationToken {
        if let Some(old) = self.subscription.take() { old.cancel(); }
        let token = self.session.child_token();
        self.subscription = Some(token.clone());
        token
    }
}

impl Drop for Requests {
    fn drop(&mut self) { self.session.cancel(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_is_request_scoped_and_disconnect_cancels_remaining_requests() {
        let durable_work = CancellationToken::new();
        let session = CancellationToken::new();
        let mut requests = Requests::new(session.clone());
        let first_id = Uuid::new_v4();
        let first = requests.admit(first_id).unwrap();
        let second = requests.admit(Uuid::new_v4()).unwrap();
        assert!(requests.cancel(first_id));
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        assert!(!durable_work.is_cancelled());
        drop(requests);
        assert!(second.is_cancelled());
        assert!(!durable_work.is_cancelled());
    }
    #[test]
    fn duplicate_ids_cannot_replace_the_original_cancellation_token() {
        let mut requests = Requests::new(CancellationToken::new());
        let id = Uuid::new_v4();
        let original = requests.admit(id).unwrap();
        assert_eq!(requests.admit(id).unwrap_err(), AdmissionError::Duplicate);
        requests.cancel(id);
        assert!(original.is_cancelled());
        requests.complete(id);
        let next = requests.admit(id).unwrap();
        assert!(!next.is_cancelled());
    }
}

#[cfg(test)]
#[test]
fn capacity_is_released_only_after_the_cancelled_request_finishes() {
    let mut requests = Requests::new(CancellationToken::new());
    let first = Uuid::new_v4();
    requests.admit(first).unwrap();
    for _ in 1..MAX_CLIENT_REQUESTS {
        requests.admit(Uuid::new_v4()).unwrap();
    }
    assert_eq!(requests.admit(Uuid::new_v4()).unwrap_err(), AdmissionError::Busy);
    requests.cancel(first);
    assert_eq!(requests.admit(Uuid::new_v4()).unwrap_err(), AdmissionError::Busy);
    requests.complete(first);
    let next_id = Uuid::new_v4();
    let next = requests.admit(next_id).unwrap();
    assert!(requests.cancel(next_id));
    assert!(next.is_cancelled());
}
