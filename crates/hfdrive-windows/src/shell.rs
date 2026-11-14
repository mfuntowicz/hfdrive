//! System-browser launch boundary.
//!
//! The provider hands the system browser exactly one `https` URL as a single
//! OS argument. There is no shell string, no command-line construction, and
//! no interpolation: the URL is validated and passed to `ShellExecuteW` as a
//! distinct parameter ([`open_in_system_browser`]).
//!
//! Failures are structured and never echo the URL or any login secret.

/// A browser launch failure. Carries the Win32 error code when one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("system browser launch failed (code {code})")]
pub struct BrowserLaunchError {
    /// Win32/HINSTANCE failure code; never contains URL content.
    pub code: u32,
}

/// Open `url` (an `https` URL) with the system default browser.
///
/// Refuses anything that is not a validated `https` URL, URLs containing
/// control characters or shell metacharacters, and inputs over 8 KiB.
pub fn open_in_system_browser(url: &str) -> Result<(), BrowserLaunchError> {
    crate::ffi::shell::open_in_system_browser(url).map_err(|e| BrowserLaunchError { code: e.code })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_boundary_refuses_unsafe_targets() {
        for bad in [
            "http://example.org/x",
            "javascript:alert(1)",
            "https://a.example/\"&whoami",
            "https://a.example/ \u{0}x",
        ] {
            assert!(open_in_system_browser(bad).is_err(), "accepted {bad:?}");
        }
    }
}
