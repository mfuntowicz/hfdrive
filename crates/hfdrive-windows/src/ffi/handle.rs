//! RAII wrappers for Windows `HANDLE` values.
//!
//! Two handle families exist and their closing rules are different:
//!
//! * Ordinary `CreateFileW`-family handles are owned by [`OwnedHandle`] and
//!   closed with `CloseHandle`.
//! * Opaque CFAPI ("protected") handles come from `CfOpenFileWithOplock`.
//!   Plain Win32 metadata/USN calls cannot service them; the supported way
//!   to inspect the object they hold is `CfReferenceProtectedHandle` +
//!   `CfGetWin32HandleFromProtectedHandle`, which yields a **borrowed** Win32
//!   handle. Per the SDK contract that Win32 handle must never be closed with
//!   `CfCloseHandle` ("in no circumstances should the caller close the Win32
//!   handle returned using CfCloseHandle"), and the reference must be
//!   released with `CfReleaseProtectedHandle` once the Win32 handle is no
//!   longer used. [`ProtectedHandle`] models exactly that sequence, and
//!   [`BorrowedWin32Handle`] is the alias type: it borrows the owner's
//!   lifetime and carries no close path, so the protected handle is closed
//!   exactly once and never twice.

use std::cell::Cell;
use std::marker::PhantomData;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, RawHandle};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::CloudFilters::{
    CfCloseHandle, CfGetWin32HandleFromProtectedHandle, CfReferenceProtectedHandle,
    CfReleaseProtectedHandle,
};

/// An owned ordinary kernel handle closed on drop.
///
/// Wraps the projection's `HANDLE` (`*mut c_void` newtype) in a safe wrapper
/// so callers never manipulate raw handle values outside this module. The
/// close routine (`CloseHandle`) runs exactly once, in `Drop`. Opaque CFAPI
/// handles are **not** represented here: they are [`ProtectedHandle`]s and
/// their alias ([`BorrowedWin32Handle`]) is never closed by anyone in this
/// module.
#[derive(Debug)]
pub(crate) struct OwnedHandle {
    raw: HANDLE,
}

// SAFETY: `OwnedHandle` owns exactly one kernel handle and closes it exactly
// once (in `Drop`). It is safe to move across threads; the kernel handle
// itself remains valid until closed.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    /// Take ownership of a raw handle returned by an OS call.
    ///
    /// # Safety
    /// `raw` must be a valid, uniquely owned handle (or null/invalid, which
    /// is rejected and yields `None`).
    pub(crate) unsafe fn from_raw(raw: HANDLE) -> Option<Self> {
        (!raw.is_invalid() && !raw.0.is_null()).then_some(Self { raw })
    }

    /// Borrow the projection handle for further API calls.
    pub(crate) fn as_win(&self) -> HANDLE {
        self.raw
    }

    /// Consume and return the raw handle without closing it.
    #[allow(dead_code)]
    pub(crate) fn into_raw(self) -> HANDLE {
        let this = std::mem::ManuallyDrop::new(self);
        this.raw
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and not yet closed; `Drop` runs exactly
        // once per `OwnedHandle`, so this close is never a double close.
        unsafe {
            let _ = CloseHandle(self.raw);
        }
    }
}

impl AsRawHandle for OwnedHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.raw.0 as RawHandle
    }
}

impl AsHandle for OwnedHandle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: the handle is alive for the borrow's lifetime.
        unsafe { BorrowedHandle::borrow_raw(self.as_raw_handle()) }
    }
}

impl FromRawHandle for OwnedHandle {
    unsafe fn from_raw_handle(raw: RawHandle) -> Self {
        // SAFETY: forwarded to the caller's ownership contract.
        match unsafe { OwnedHandle::from_raw(HANDLE(raw as *mut core::ffi::c_void)) } {
            Some(handle) => handle,
            None => panic!("null/invalid handle passed to OwnedHandle::from_raw_handle"),
        }
    }
}

impl IntoRawHandle for OwnedHandle {
    fn into_raw_handle(self) -> RawHandle {
        self.into_raw().0 as RawHandle
    }
}

// ---------------------------------------------------------------------------
// Handle views: Win32 metadata queries vs CFAPI placeholder calls
// ---------------------------------------------------------------------------

/// A handle view usable for Win32 metadata/USN queries
/// (`GetFileInformationByHandleEx`, `DeviceIoControl`, …).
///
/// Implemented by ordinary [`OwnedHandle`]s and by the borrowed alias of a
/// protected handle — never by [`ProtectedHandle`] itself, so the opaque
/// CFAPI handle can never reach a Win32 metadata call by accident.
pub(crate) trait Win32Handle {
    fn as_win32(&self) -> HANDLE;
}

impl Win32Handle for OwnedHandle {
    fn as_win32(&self) -> HANDLE {
        self.raw
    }
}

/// A handle view usable for CFAPI placeholder calls (`CfSetInSyncState`, …):
/// either an opaque [`ProtectedHandle`] or an ordinary handle the CFAPI
/// entry points accept (e.g. the plain read/write open in
/// `convert_published`).
pub(crate) trait CfaHandle {
    fn as_cfa(&self) -> HANDLE;
}

impl CfaHandle for OwnedHandle {
    fn as_cfa(&self) -> HANDLE {
        self.raw
    }
}

// ---------------------------------------------------------------------------
// Protected CFAPI handles -> borrowed Win32 handles
// ---------------------------------------------------------------------------

/// The four protected-handle calls the borrow sequence needs. Production
/// calls forward to `cldapi.dll`; tests substitute a scripted recorder so
/// the borrow/replace/close accounting is deterministic without a registered
/// sync root.
///
/// # Safety
/// Implementations must perform exactly the named CFAPI operation on the
/// given live protected handle, with the SDK's documented lifetime rules.
pub(crate) trait ProtectedHandleOps {
    /// `CfReferenceProtectedHandle`.
    unsafe fn reference(&self, protected: HANDLE) -> bool;
    /// `CfGetWin32HandleFromProtectedHandle` (only after a reference).
    unsafe fn convert(&self, protected: HANDLE) -> HANDLE;
    /// `CfReleaseProtectedHandle` (exactly once per taken reference).
    unsafe fn release(&self, protected: HANDLE);
    /// `CfCloseHandle` (exactly once per owned protected handle).
    unsafe fn close(&self, protected: HANDLE);
}

/// Production policy: the real `cldapi.dll` calls.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CfaProtectedOps;

// SAFETY: each method is a direct forwarding call to the documented CFAPI
// function for the given live protected handle.
impl ProtectedHandleOps for CfaProtectedOps {
    unsafe fn reference(&self, protected: HANDLE) -> bool {
        unsafe { CfReferenceProtectedHandle(protected) }
    }

    unsafe fn convert(&self, protected: HANDLE) -> HANDLE {
        unsafe { CfGetWin32HandleFromProtectedHandle(protected) }
    }

    unsafe fn release(&self, protected: HANDLE) {
        unsafe { CfReleaseProtectedHandle(protected) }
    }

    unsafe fn close(&self, protected: HANDLE) {
        let _ = unsafe { CfCloseHandle(protected) };
    }
}

/// The borrowed Win32 handle produced from a protected CFAPI handle.
///
/// It borrows its lifetime from the [`ProtectedHandle`] it was derived from
/// (enforced by [`ProtectedHandle::win32`]) and it **never closes itself**:
/// closing this alias would double-close the underlying object handle that
/// the protected handle still owns and closes with `CfCloseHandle`. The
/// reference taken on the protected handle is released when the owner is
/// dropped, so at most one alias exists per owner — exactly the SDK's
/// reference/convert/use/release sequence.
#[derive(Debug)]
pub(crate) struct BorrowedWin32Handle<'a, O: ProtectedHandleOps = CfaProtectedOps> {
    raw: HANDLE,
    _owner: PhantomData<&'a ProtectedHandle<O>>,
}

// Hand-written `Clone`/`Copy`: the derived forms would demand
// `O: Clone`/`O: Copy`, which the scripted test policies do not (and need
// not) satisfy. Copying the alias copies only the handle value; it never
// closes anything and never duplicates a reference.
impl<'a, O: ProtectedHandleOps> Clone for BorrowedWin32Handle<'a, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, O: ProtectedHandleOps> Copy for BorrowedWin32Handle<'a, O> {}

impl<'a, O: ProtectedHandleOps> Win32Handle for BorrowedWin32Handle<'a, O> {
    fn as_win32(&self) -> HANDLE {
        self.raw
    }
}

/// An owned opaque protected CFAPI handle (`CfOpenFileWithOplock`).
///
/// The handle is closed exactly once, by the policy's `close`
/// (`CfCloseHandle`). While a borrowed Win32 alias exists (through
/// [`ProtectedHandle::win32`]) the handle is referenced so the OS keeps it
/// alive across the alias' use; that reference is released when this owner
/// is dropped. Dropping with no alias alive still closes exactly once.
pub(crate) struct ProtectedHandle<O: ProtectedHandleOps = CfaProtectedOps> {
    raw: HANDLE,
    ops: O,
    /// Are we holding one `CfReferenceProtectedHandle` reference right now?
    referenced: Cell<bool>,
}

// SAFETY: the production policy is pure `cldapi.dll` call glue; the handle
// owns exactly one kernel handle closed exactly once. Test policies are not
// `Send` (they carry interior log handles) and make no such claim.
unsafe impl Send for ProtectedHandle<CfaProtectedOps> {}

impl<O: ProtectedHandleOps> ProtectedHandle<O> {
    /// Take ownership of an opaque protected handle returned by
    /// `CfOpenFileWithOplock` under policy `ops`.
    ///
    /// # Safety
    /// `raw` must be a valid, uniquely owned protected handle (or
    /// null/invalid, which is rejected and yields `None`).
    pub(crate) unsafe fn from_raw_with(raw: HANDLE, ops: O) -> Option<Self> {
        (!raw.is_invalid() && !raw.0.is_null()).then_some(Self {
            raw,
            ops,
            referenced: Cell::new(false),
        })
    }

    /// Convert to the Win32 handle for metadata/USN queries **on the same
    /// open**, borrowed for `'a` and never closed by the borrower.
    ///
    /// This is the G08 sequence: `CfReferenceProtectedHandle` (which keeps
    /// the use tracked and synchronizes with the oplock break
    /// acknowledgment), then `CfGetWin32HandleFromProtectedHandle`. The
    /// reference is held until this [`ProtectedHandle`] is dropped, so the
    /// alias cannot outlive the object handle it was derived from. A failed
    /// reference, an already-held reference or a null/invalid conversion
    /// result yields `None`; partial state is released immediately so no
    /// close ever runs twice.
    pub(crate) fn win32(&self) -> Option<BorrowedWin32Handle<'_, O>> {
        if self.referenced.get() {
            // A second alias in the same owner would need a second
            // reference, and `Drop` releases exactly one. Refuse instead of
            // leaking an unbalanced reference.
            return None;
        }
        // SAFETY: `self.raw` is a live protected handle owned here.
        if !unsafe { self.ops.reference(self.raw) } {
            return None;
        }
        // SAFETY: the protected handle is referenced for the whole borrow;
        // the returned Win32 handle is only read through `as_win`/`as_win32`
        // and is never closed here ("in no circumstances should the caller
        // close the Win32 handle returned using CfCloseHandle").
        let raw = unsafe { self.ops.convert(self.raw) };
        if raw.is_invalid() || raw.0.is_null() {
            // SAFETY: the reference taken above is released exactly once.
            unsafe { self.ops.release(self.raw) };
            return None;
        }
        self.referenced.set(true);
        Some(BorrowedWin32Handle {
            raw,
            _owner: PhantomData,
        })
    }
}

impl<O: ProtectedHandleOps> CfaHandle for ProtectedHandle<O> {
    fn as_cfa(&self) -> HANDLE {
        self.raw
    }
}

impl<O: ProtectedHandleOps> Drop for ProtectedHandle<O> {
    fn drop(&mut self) {
        // SAFETY: the protected handle is owned and not yet closed. If a
        // Win32 alias was derived, its reference is released here — once —
        // before the single `close`, so the handle is closed exactly once
        // even when metadata was queried through the alias.
        unsafe {
            if self.referenced.get() {
                self.ops.release(self.raw);
            }
            self.ops.close(self.raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;

    /// One scripted protected handle's call journal, shared with the test so
    /// the accounting is observable after the owner is dropped.
    #[derive(Clone)]
    struct Journal(Rc<std::cell::RefCell<Vec<(&'static str, usize)>>>);

    impl Journal {
        fn new() -> Self {
            Self(Rc::new(std::cell::RefCell::new(Vec::new())))
        }

        fn count(&self, name: &'static str) -> usize {
            self.0.borrow().iter().filter(|(op, _)| *op == name).count()
        }

        fn closes_of(&self, value: usize) -> usize {
            self.0
                .borrow()
                .iter()
                .filter(|(op, raw)| *op == "close" && *raw == value)
                .count()
        }

        fn releases_of(&self, value: usize) -> usize {
            self.0
                .borrow()
                .iter()
                .filter(|(op, raw)| *op == "release" && *raw == value)
                .count()
        }
    }

    /// Scripted [`ProtectedHandleOps`] that records every call and the
    /// handle value it ran against: borrowed-lifetime and double-close
    /// behavior is deterministic without a registered sync root.
    struct ScriptedOps {
        journal: Journal,
        /// Whether the reference succeeds (models `FALSE` failures).
        reference_ok: bool,
        /// Value the conversion returns (models a null/invalid alias).
        alias: Option<usize>,
    }

    // SAFETY: test-only recording glue; the real calls are covered by
    // `CfaProtectedOps` forwarding to `cldapi.dll`.
    impl ProtectedHandleOps for ScriptedOps {
        unsafe fn reference(&self, protected: HANDLE) -> bool {
            self.journal
                .0
                .borrow_mut()
                .push(("reference", protected.0 as usize));
            self.reference_ok
        }

        unsafe fn convert(&self, protected: HANDLE) -> HANDLE {
            self.journal
                .0
                .borrow_mut()
                .push(("convert", protected.0 as usize));
            match self.alias {
                Some(value) => HANDLE(value as _),
                None => HANDLE(std::ptr::null_mut()),
            }
        }

        unsafe fn release(&self, protected: HANDLE) {
            self.journal
                .0
                .borrow_mut()
                .push(("release", protected.0 as usize));
        }

        unsafe fn close(&self, protected: HANDLE) {
            self.journal
                .0
                .borrow_mut()
                .push(("close", protected.0 as usize));
        }
    }

    fn owner(raw: usize, alias: Option<usize>) -> (ProtectedHandle<ScriptedOps>, Journal) {
        let journal = Journal::new();
        let ops = ScriptedOps {
            journal: journal.clone(),
            reference_ok: true,
            alias,
        };
        let handle = unsafe {
            ProtectedHandle::from_raw_with(HANDLE(raw as _), ops).expect("valid protected handle")
        };
        (handle, journal)
    }

    /// Borrowed lifetime: the Win32 alias is borrowed from its owner and is
    /// never closed by the borrower — the owner releases the reference and
    /// closes the protected handle exactly once.
    #[test]
    fn borrowed_win32_alias_is_never_closed_by_the_borrower() {
        let (handle, journal) = owner(0x1000, Some(0x2000));
        {
            let alias = handle.win32().expect("reference + convert succeed");
            assert_eq!(alias.as_win32(), HANDLE(0x2000 as _));
            assert_eq!(handle.as_cfa(), HANDLE(0x1000 as _));
            // The alias is `Copy` with no `Drop`: copying it and letting it
            // leave this scope runs nothing at all (there is no destructor
            // to run), which is the borrowed-lifetime guarantee. Release is
            // exercised through the owner's real API below.
            let copied = alias;
            assert_eq!(copied.as_win32(), alias.as_win32());
        }
        assert_eq!(
            journal.count("close"),
            0,
            "the borrower's scope ending must not close anything"
        );
        assert_eq!(
            journal.count("release"),
            0,
            "no reference is released by the borrower"
        );
        drop(handle);
        assert_eq!(journal.count("reference"), 1);
        assert_eq!(journal.count("convert"), 1);
        assert_eq!(
            journal.releases_of(0x1000),
            1,
            "reference released exactly once, by the owner"
        );
        assert_eq!(
            journal.closes_of(0x1000),
            1,
            "protected handle closed exactly once"
        );
        assert_eq!(
            journal.closes_of(0x2000),
            0,
            "the borrowed alias is never closed"
        );
    }

    /// Even with a metadata query through the alias, the protected handle is
    /// closed exactly once and the alias value never is: no double close of
    /// the protected handle (once via alias, once via owner).
    #[test]
    fn protected_handle_is_closed_exactly_once_not_twice() {
        let (handle, journal) = owner(0x1000, Some(0x2000));
        let alias = handle.win32().expect("borrow");
        // Metadata/USN queries use `alias.as_win32()` here; nothing closes it.
        let _query_value = alias.as_win32();
        drop(handle);
        assert_eq!(journal.count("release"), 1);
        assert_eq!(journal.count("close"), 1, "one owner lifetime, one close");
        assert_eq!(journal.closes_of(0x2000), 0);
    }

    /// A replaced object at the same path yields a fresh owner with a
    /// different alias; a stale alias from the previous open can never be
    /// reused for the new object, and each open closes exactly once.
    #[test]
    fn replacement_between_opens_never_reuses_a_stale_alias() {
        let (first, first_journal) = owner(0x1000, Some(0x2000));
        let first_alias = first.win32().expect("first borrow").as_win32();
        drop(first);
        assert_eq!(first_journal.closes_of(0x1000), 1);

        // The object was replaced: a new open is a new owner/alias pair.
        let (second, second_journal) = owner(0x1001, Some(0x2001));
        let second_alias = second.win32().expect("second borrow").as_win32();
        assert_ne!(
            first_alias, second_alias,
            "a replacement object's alias differs; a stale alias is never reused"
        );
        drop(second);
        assert_eq!(second_journal.closes_of(0x1001), 1);
        assert_eq!(first_journal.closes_of(0x1001), 0, "no cross-owner close");
        assert_eq!(second_journal.closes_of(0x1000), 0, "no cross-owner close");
    }

    /// A failed reference or a failed conversion takes no reference and
    /// closes exactly once; the failed conversion releases its own partial
    /// reference immediately (nothing leaks, nothing closes twice).
    #[test]
    fn failed_borrow_takes_no_unbalanced_reference_and_closes_once() {
        let journal = Journal::new();
        let ops = ScriptedOps {
            journal: journal.clone(),
            reference_ok: false,
            alias: Some(0x2000),
        };
        let handle = unsafe { ProtectedHandle::from_raw_with(HANDLE(0x1000 as _), ops) }.unwrap();
        assert!(handle.win32().is_none(), "failed reference yields no alias");
        drop(handle);
        assert_eq!(journal.count("release"), 0);
        assert_eq!(journal.closes_of(0x1000), 1);

        let journal = Journal::new();
        let ops = ScriptedOps {
            journal: journal.clone(),
            reference_ok: true,
            alias: None,
        };
        let handle = unsafe { ProtectedHandle::from_raw_with(HANDLE(0x1000 as _), ops) }.unwrap();
        assert!(
            handle.win32().is_none(),
            "failed conversion yields no alias"
        );
        drop(handle);
        assert_eq!(
            journal.releases_of(0x1000),
            1,
            "partial reference released at once"
        );
        assert_eq!(journal.closes_of(0x1000), 1);
    }

    /// One owner holds at most one reference: a second borrow is refused
    /// instead of leaking a second reference the single release could never
    /// balance. The alias merely leaves scope (it has no destructor); the
    /// single release happens through the owner's real drop API.
    #[test]
    fn one_reference_per_owner_is_never_leaked() {
        let (handle, journal) = owner(0x1000, Some(0x2000));
        {
            let first = handle.win32().expect("first borrow");
            assert!(
                handle.win32().is_none(),
                "second borrow of one owner is refused instead of leaking a reference"
            );
            assert_eq!(first.as_win32(), HANDLE(0x2000 as _));
        }
        drop(handle);
        assert_eq!(journal.count("reference"), 1);
        assert_eq!(journal.count("release"), 1);
        assert_eq!(journal.count("close"), 1);
    }

    /// The borrowed alias can be used alongside the owner's CFAPI handle:
    /// guard queries (alias) and the mutation (`as_cfa`) run on the *same*
    /// open, so no replacement can slip in between them.
    #[test]
    fn alias_and_cfa_view_share_one_open() {
        let (handle, journal) = owner(0x1000, Some(0x2000));
        let alias = handle.win32().expect("borrow");
        // Guard query on the alias, mutation on the protected handle: both
        // alive at once (this compiles only because `win32` borrows `&self`).
        let _guarded = alias.as_win32();
        let _mutating = handle.as_cfa();
        drop(handle);
        assert_eq!(journal.count("release"), 1);
        assert_eq!(journal.count("close"), 1);
    }
}
