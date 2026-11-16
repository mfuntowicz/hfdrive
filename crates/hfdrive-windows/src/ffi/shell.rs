//! Safe wrappers over `ShellExecuteW` for launching the system browser.
//!
//! The URL is passed as a **separate OS parameter** to `ShellExecuteW`; no
//! command line is built and no shell-string interpolation ever happens.
//! Only a validated `https` URL with no embedded quoting-relevant control
//! characters is accepted; on any doubt the launch is refused.

use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

/// Failure of a browser launch attempt. Carries the Win32 error code when the
/// OS reported one; never contains the target URL or any secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchError {
    pub code: u32,
}

/// Maximum accepted URL length for a system-browser launch (8 KiB).
const MAX_URL_BYTES: usize = 8 * 1024;

/// Validate a `https` URL for shell launch.
///
/// Rejects anything that is not exactly `https://` followed by a host,
/// controls, spaces, quotes or backslashes, embedded NUL, and over-long input.
/// `&` is explicitly allowed: it separates query parameters and has no shell
/// meaning here because `ShellExecuteW` receives the URL directly, never a
/// command line. The caller parses the URL separately as well.
pub(crate) fn validate_launch_url(url: &str) -> Result<(), LaunchError> {
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(LaunchError { code: 87 }); // ERROR_INVALID_PARAMETER
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(LaunchError { code: 87 });
    };
    if rest.is_empty() {
        return Err(LaunchError { code: 87 });
    }
    for c in url.chars() {
        // Controls, spaces, quotes and path/shell syntax that could confuse
        // the launch boundary are refused. Query separators are not commands.
        if c <= ' ' || c == '\u{7f}' || matches!(c, '"' | '\'' | '`' | '$' | '|' | ';' | '<' | '>' | '\\') {
            return Err(LaunchError { code: 87 });
        }
    }
    Ok(())
}

/// Open `url` in the system default handler for `https`.
///
/// The operation is `open`; no parameters string is passed (the URL is the
/// file operand), so there is nothing to quote and nothing to interpolate.
pub(crate) fn open_in_system_browser(url: &str) -> Result<(), LaunchError> {
    validate_launch_url(url)?;
    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let operation: Vec<u16> = "open\0".encode_utf16().collect();

    // SAFETY: `wide`/`operation` are NUL-terminated UTF-16 buffers valid for
    // the duration of the call; no other parameters are supplied.
    let result: HINSTANCE = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW reports failure as a return value <= 32.
    if result.0 as usize <= 32 {
        return Err(LaunchError { code: result.0 as u32 });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_and_metacharacters() {
        assert!(validate_launch_url("http://huggingface.co/oauth/authorize").is_err());
        assert!(validate_launch_url("file:///etc/passwd").is_err());
        assert!(validate_launch_url("https://huggingface.co/a b").is_err());
        assert!(validate_launch_url("https://huggingface.co/a\"&calc.exe").is_err());
        assert!(validate_launch_url("").is_err());
        assert!(validate_launch_url(&("https://x".to_owned() + &"a".repeat(MAX_URL_BYTES))).is_err());
        assert!(validate_launch_url("https://huggingface.co/oauth/authorize?x=1#f").is_ok());
        assert!(validate_launch_url(
            "https://huggingface.co/oauth/authorize?client_id=fb5faab4-e580-4b13-84d6-1b9217966b8e&redirect_uri=http%3A%2F%2F127.0.0.1%2Foauth%2Fcallback&response_type=code&scope=openid+profile"
        ).is_ok());
    }
}
