use hfdrive_protocol::{
    Body, ClientRole, Envelope, ExitProviderRequest, GetStatusRequest, HelloRequest,
    ProtocolErrorCode, Request, ResponseResult, StartLoginRequest, StatusSnapshot, SubscribeStatusRequest,
    read_envelope, write_envelope, write_frame,
};
use hfdrive_provider::{Provider, serve};
use std::{sync::Arc, time::Duration};
use tokio::io::{DuplexStream, duplex};
use uuid::Uuid;

async fn receive(stream: &mut DuplexStream) -> Option<Envelope> {
    tokio::time::timeout(Duration::from_secs(5), read_envelope(stream)).await.unwrap().unwrap()
}

async fn hello(stream: &mut DuplexStream) {
    let id = Uuid::new_v4();
    write_envelope(stream, &Envelope::request(id, Request::Hello(HelloRequest {
        protocol_major: 1, protocol_minor: 0, role: ClientRole::Cli,
        build_version: "test".into(),
    }))).await.unwrap();
    let response = receive(stream).await.unwrap();
    assert_eq!(response.request_id, id);
    assert!(matches!(response.body, Body::Response { outcome: Ok(ResponseResult::Hello(_)) }));
}

#[tokio::test]
async fn foreign_major_gets_supported_hello_then_connection_closes() {
    let provider = Arc::new(Provider::new(StatusSnapshot { sequence: 0, account: Default::default(), connections: Vec::new() }));
    let (server, mut client) = duplex(4096);
    let task = tokio::spawn(serve(server, provider.clone()));
    write_frame(&mut client, br#"{"protocol_major":2,"protocol_minor":0,"request_id":"11111111-1111-4111-8111-111111111111","kind":"request","method":"hello","body":{"protocol_major":2,"protocol_minor":0,"role":"cli","build_version":"foreign"}}"#).await.unwrap();
    let response = receive(&mut client).await.unwrap();
    let Body::Response { outcome: Ok(ResponseResult::Hello(hello)) } = response.body else { panic!("expected negotiation response"); };
    assert_eq!(hello.protocol_major, 1);
    assert!(receive(&mut client).await.is_none());
    task.await.unwrap();
    assert!(!provider.shutdown.is_cancelled());
}

#[tokio::test]
async fn shutdown_command_cannot_execute_before_hello() {
    let provider = Arc::new(Provider::new(StatusSnapshot { sequence: 0, account: Default::default(), connections: Vec::new() }));
    let (server, mut client) = duplex(4096);
    let task = tokio::spawn(serve(server, provider.clone()));
    write_envelope(&mut client, &Envelope::request(Uuid::new_v4(), Request::ExitProvider(ExitProviderRequest {
        operation_id: Uuid::new_v4(),
    }))).await.unwrap();
    assert!(receive(&mut client).await.is_none());
    task.await.unwrap();
    assert!(!provider.shutdown.is_cancelled());
}

#[tokio::test]
async fn subscription_recovers_full_snapshot_and_exit_ack_precedes_shutdown() {
    let provider = Arc::new(Provider::new(StatusSnapshot { sequence: 42, account: Default::default(), connections: Vec::new() }));
    let (server, mut client) = duplex(4096);
    let task = tokio::spawn(serve(server, provider.clone()));
    hello(&mut client).await;
    let subscribe_id = Uuid::new_v4();
    write_envelope(&mut client, &Envelope::request(subscribe_id, Request::SubscribeStatus(SubscribeStatusRequest {
        last_sequence: Some(1),
    }))).await.unwrap();
    let response = receive(&mut client).await.unwrap();
    assert_eq!(response.request_id, subscribe_id);
    let Body::Response { outcome: Ok(ResponseResult::SubscribeStatus(result)) } = response.body else { panic!("expected snapshot"); };
    assert!(result.subscribed);
    assert_eq!(result.snapshot.sequence, 42);

    let status_id = Uuid::new_v4();
    write_envelope(&mut client, &Envelope::request(status_id, Request::GetStatus(GetStatusRequest {}))).await.unwrap();
    let response = receive(&mut client).await.unwrap();
    assert_eq!(response.request_id, status_id);
    let Body::Response { outcome: Ok(ResponseResult::GetStatus(result)) } = response.body else { panic!("expected status"); };
    assert_eq!(result.event_sequence, 42);

    let exit_id = Uuid::new_v4();
    write_envelope(&mut client, &Envelope::request(exit_id, Request::ExitProvider(ExitProviderRequest {
        operation_id: Uuid::new_v4(),
    }))).await.unwrap();
    let response = receive(&mut client).await.unwrap();
    assert_eq!(response.request_id, exit_id);
    assert!(matches!(response.body, Body::Response { outcome: Ok(ResponseResult::ExitProvider(result)) } if result.accepted));
    task.await.unwrap();
    assert!(provider.shutdown.is_cancelled());
}

#[tokio::test]
async fn rejected_login_and_exit_have_distinct_durable_ids() {
    let provider = Arc::new(Provider::new(StatusSnapshot { sequence: 0, account: Default::default(), connections: Vec::new() }));
    let (server, mut client) = duplex(4096);
    let task = tokio::spawn(serve(server, provider.clone()));
    hello(&mut client).await;
    let login_id = Uuid::new_v4();
    write_envelope(&mut client, &Envelope::request(login_id, Request::StartLogin(StartLoginRequest {
        operation_id: Uuid::new_v4(), flow: hfdrive_protocol::LoginFlow::Pkce,
        purpose: hfdrive_protocol::LoginPurpose::Signin, organization_id: None,
    }))).await.unwrap();
    let Body::Response { outcome: Err(error) } = receive(&mut client).await.unwrap().body else { panic!("unconfigured login must fail"); };
    assert_eq!(error.code, ProtocolErrorCode::OAuthClientNotConfigured);
    let status_id = Uuid::new_v4();
    write_envelope(&mut client, &Envelope::request(status_id, Request::GetStatus(GetStatusRequest {}))).await.unwrap();
    assert_eq!(receive(&mut client).await.unwrap().request_id, status_id, "a rejected command must not close the client");
    let exit_id = Uuid::new_v4();
    write_envelope(&mut client, &Envelope::request(exit_id, Request::ExitProvider(ExitProviderRequest {
        operation_id: Uuid::new_v4(),
    }))).await.unwrap();
    let response = receive(&mut client).await.unwrap();
    assert_eq!(response.request_id, exit_id);
    assert!(matches!(response.body, Body::Response { outcome: Ok(ResponseResult::ExitProvider(_)) }));
    task.await.unwrap();
}

#[tokio::test]
async fn exit_ledger_does_not_authorize_shutdown_on_replay() {
    let provider = Arc::new(Provider::new(StatusSnapshot { sequence: 0, account: Default::default(), connections: Vec::new() }));
    let operation_id = Uuid::new_v4();
    provider.state.begin_operation(hfdrive_state::BeginOperationRequest {
        operation_id: hfdrive_core::ids::OperationId::from_uuid(operation_id).unwrap(),
        kind: "exit_provider".into(), request: serde_json::json!({"operation_id": operation_id}),
        effect_class: hfdrive_state::EffectClass::Local, account_key: None, connection_id: None,
        bucket_creation_operation_id: None,
    }).await.unwrap();
    provider.state.finish_operation(hfdrive_core::ids::OperationId::from_uuid(operation_id).unwrap(),
        serde_json::json!({"accepted": true})).await.unwrap();
    let (server, mut client) = duplex(4096);
    let task = tokio::spawn(serve(server, provider.clone()));
    hello(&mut client).await;
    write_envelope(&mut client, &Envelope::request(Uuid::new_v4(), Request::ExitProvider(ExitProviderRequest {
        operation_id,
    }))).await.unwrap();
    let response = receive(&mut client).await.unwrap();
    assert!(matches!(response.body, Body::Response { outcome: Ok(ResponseResult::ExitProvider(_)) }));
    drop(client);
    task.await.unwrap();
    assert!(!provider.shutdown.is_cancelled(), "a persisted receipt from another provider lifetime is not an exit command");
}

#[tokio::test]
async fn externally_pending_login_is_replayed_as_pending_not_started_again() {
    let provider = Arc::new(Provider::new(StatusSnapshot {
        sequence: 0,
        account: Default::default(),
        connections: Vec::new(),
    }));
    let request = StartLoginRequest {
        operation_id: Uuid::new_v4(),
        flow: hfdrive_protocol::LoginFlow::Pkce,
        purpose: hfdrive_protocol::LoginPurpose::Signin,
        organization_id: None,
    };
    let operation_id = hfdrive_core::ids::OperationId::from_uuid(request.operation_id).unwrap();
    let request_value = serde_json::to_value(Request::StartLogin(request.clone())).unwrap();
    provider.state.begin_operation(hfdrive_state::BeginOperationRequest {
        operation_id,
        kind: "start_login".into(),
        request: request_value,
        effect_class: hfdrive_state::EffectClass::External,
        account_key: None,
        connection_id: None,
        bucket_creation_operation_id: None,
    }).await.unwrap();
    provider.state.mark_dispatched(operation_id).await.unwrap();

    let (server, mut client) = duplex(4096);
    let task = tokio::spawn(serve(server, provider.clone()));
    hello(&mut client).await;
    write_envelope(&mut client, &Envelope::request(Uuid::new_v4(), Request::StartLogin(request))).await.unwrap();
    let Body::Response { outcome: Err(error) } = receive(&mut client).await.unwrap().body else {
        panic!("an externally pending operation must not execute again");
    };
    assert_eq!(error.code, ProtocolErrorCode::Busy);
    drop(client);
    task.await.unwrap();
}
