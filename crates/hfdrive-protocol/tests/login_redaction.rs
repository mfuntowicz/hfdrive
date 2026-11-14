use hfdrive_protocol::{ResponseResult, StartLoginResult};
use uuid::Uuid;

#[test]
fn transient_login_instructions_are_not_nested_debug_output() {
    let result = ResponseResult::StartLogin(StartLoginResult {
        session_id: Uuid::new_v4(),
        authorization_url: Some("https://huggingface.co/oauth/authorize?state=MARKER-STATE".into()),
        user_code: Some("MARKER-USER-CODE".into()),
        verification_uri: Some("https://huggingface.co/oauth/device?user_code=MARKER-CODE".into()),
        expires_at: "2026-11-13T18:00:00Z".into(),
    });
    assert!(!format!("{result:?}").contains("MARKER"));
}
