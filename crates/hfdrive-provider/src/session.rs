use crate::{OutgoingEnvelope, Provider, stream_status, requests::{AdmissionError, MAX_CLIENT_REQUESTS, Requests}};
use hfdrive_protocol::{
    Body, CancelRequestResult, Envelope, ProtocolError, ProtocolErrorCode, Request,
    ResponseResult, SubscribeStatusResult,
    read_envelope, read_frame, write_envelope,
};
use std::{sync::Arc, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::{Mutex, mpsc}, task::JoinSet};

/// The caller must authenticate the Windows peer before entering this function.
pub async fn serve<S>(mut stream: S, provider: Arc<Provider>)
where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    let hello = tokio::select! {
        _ = provider.shutdown.cancelled() => return,
        result = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut stream)) => {
            match result {
                Ok(Ok(Some(bytes))) => Envelope::parse_handshake(&bytes),
                _ => return,
            }
        }
    };
    let Ok(hello) = hello else { return; };
    let Body::Request(Request::Hello(request)) = hello.body else { return; };
    let compatible = hello.protocol_major == 1 && hello.protocol_minor == 0;
    let reply = Envelope::response(hello.request_id, "hello", Ok(provider.hello(request)));
    if !matches!(tokio::time::timeout(Duration::from_secs(10), write_envelope(&mut stream, &reply)).await, Ok(Ok(()))) || !compatible { return; }

    let session = provider.shutdown.child_token();
    let requests = Arc::new(Mutex::new(Requests::new(session.clone())));
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (incoming_tx, mut incoming_rx) = mpsc::channel(MAX_CLIENT_REQUESTS);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<OutgoingEnvelope>(MAX_CLIENT_REQUESTS);
    let reader_cancel = session.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            // Only connection shutdown may interrupt an in-progress frame read.
            let frame = tokio::select! {
                _ = reader_cancel.cancelled() => break,
                frame = read_envelope(&mut reader) => frame,
            };
            match frame {
                Ok(Some(envelope)) => {
                    if incoming_tx.send(envelope).await.is_err() { break; }
                }
                _ => break,
            }
        }
        reader_cancel.cancel();
    });
    let writer_cancel = session.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            let envelope = tokio::select! {
                _ = writer_cancel.cancelled() => break,
                envelope = outgoing_rx.recv() => envelope,
            };
            let Some(outgoing) = envelope else { break; };
            let OutgoingEnvelope { envelope, after } = outgoing;
            let sent = tokio::select! {
                _ = writer_cancel.cancelled() => break,
                sent = write_envelope(&mut writer, &envelope) => sent,
            };
            // Shutdown is acknowledged only after the writer's actual send
            // attempt. On disconnect, dropping `after` still lets the accepted
            // provider shutdown proceed without a connected waiter.
            drop(after);
            if sent.is_err() { break; }
        }
        writer_cancel.cancel();
    });

    let mut work = JoinSet::new();
    loop {
        let envelope = tokio::select! {
            _ = session.cancelled() => break,
            result = work.join_next(), if !work.is_empty() => {
                if result.is_some_and(|result| result.is_err()) { session.cancel(); }
                continue;
            }
            envelope = incoming_rx.recv() => envelope,
        };
        let Some(envelope) = envelope else { break; };
        let Body::Request(request) = envelope.body else { break; };
        let id = envelope.request_id;
        let method = request.method();
        if matches!(request, Request::Hello(_)) { break; }
        if requests.lock().await.is_active(id) { break; }
        let request = match request {
            Request::CancelRequest(request) => {
                let accepted = requests.lock().await.cancel(request.target_request_id);
                let result = ResponseResult::CancelRequest(CancelRequestResult { accepted });
                if outgoing_tx.send(OutgoingEnvelope::new(Envelope::response(id, method, Ok(result)))).await.is_err() { break; }
                continue;
            }
            Request::SubscribeStatus(_) => {
                let cancellation = requests.lock().await.replace_subscription();
                let (snapshot, receiver) = provider.subscribe();
                let result = ResponseResult::SubscribeStatus(SubscribeStatusResult { subscribed: true, snapshot });
                if outgoing_tx.send(OutgoingEnvelope::new(Envelope::response(id, method, Ok(result)))).await.is_err() { break; }
                work.spawn(stream_status(receiver, cancellation, outgoing_tx.clone()));
                continue;
            }
            request => request,
        };
        let cancellation = match requests.lock().await.admit(id) {
            Ok(cancellation) => cancellation,
            Err(error) => {
                let error = ProtocolError {
                    code: if error == AdmissionError::Busy { ProtocolErrorCode::Busy } else { ProtocolErrorCode::InvalidRequest },
                    message: error.to_string(),
                    retry_after_ms: Some(200),
                };
                if outgoing_tx.send(OutgoingEnvelope::new(Envelope::response(id, method, Err(error)))).await.is_err() { break; }
                continue;
            }
        };
        let provider = provider.clone();
        let outgoing = outgoing_tx.clone();
        let requests = requests.clone();
        work.spawn(async move {
            let reply = provider.dispatch(request, cancellation).await;
            requests.lock().await.complete(id);
            // The writer owns the post-reply action until its actual send
            // attempt; a disconnected waiter drops it and cannot strand exit.
            let _ = outgoing.send(OutgoingEnvelope {
                envelope: Envelope::response(id, method, reply.result),
                after: reply.after,
            }).await;
        });
    }
    session.cancel();
    drop(incoming_rx);
    drop(outgoing_tx);
    work.abort_all();
    while work.join_next().await.is_some() {}
    let _ = reader_task.await;
    let _ = writer_task.await;
}
