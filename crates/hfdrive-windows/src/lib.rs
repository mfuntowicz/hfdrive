//! Windows adapters for HF Drive.
//!
//! This crate owns the Windows-specific pieces of the provider boundary:
//!
//! * [`credentials`] — user-scoped DPAPI protection and atomic, ACL'd
//!   credential record storage (OAuth/S3 envelopes). Plaintext is carried in
//!   zeroizing buffers and never logged.
//! * [`ownership`] — the single-provider-per-user lease (secured named mutex
//!   + exclusive state-owner file lock), distinguishing "already running in
//!   this session" from "running in another session".
//! * [`ipc`] — the authenticated per-user named-pipe boundary. Both sides
//!   verify the other's token identity (user SID, logon SID, session,
//!   integrity, package identity, image path) **before any protocol byte**;
//!   the returned stream implements `tokio::io::AsyncRead`/`AsyncWrite` for
//!   `hfdrive-protocol` framing to layer on top.
//! * [`shell`] — the system-browser launch boundary: one validated `https`
//!   URL as a single OS argument, never a shell command string.
//!
//! * [`filesystem`] — validated NTFS roots, coherent snapshots and bounded change observation.
//! * [`cfapi`] — registered Explorer roots, immutable placeholder identities and guarded transfers.
//!
//! # Non-secret errors
//!
//! Every error type ([`CredentialError`], [`OwnershipError`], [`IpcError`])
//! is structured and free of secret material; OS failures carry Win32 codes
//! so callers can classify retry-vs-fail without string matching.

#![cfg_attr(not(windows), allow(unused))]

mod error;
mod ffi;

pub mod cfapi;
pub mod filesystem;
pub mod credentials;
pub mod ipc;
pub mod ownership;
pub mod shell;

pub use error::{CredentialError, IpcError, OwnershipError};
