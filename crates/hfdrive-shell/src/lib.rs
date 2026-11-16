mod contract;

use contract::{build_request_json, child_title, parse_targets, MAX_JSON_BYTES, MAX_PATH_CHARS, MAX_SOURCES};
use hfdrive_protocol::ImportTarget;
use std::cell::Cell;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicIsize, Ordering};
use windows::core::{w, Error, GUID, Interface, PCWSTR, PWSTR, Ref, Result as WinResult};
use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOTIMPL, E_POINTER, ERROR_SUCCESS, HMODULE};
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
use windows::Win32::System::Com::{CoTaskMemFree, IClassFactory, IClassFactory_Impl, IBindCtx};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::Threading::{CreateProcessW, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW};
use windows::Win32::UI::Shell::{
    IEnumExplorerCommand, IEnumExplorerCommand_Impl, IExplorerCommand, IExplorerCommand_Impl, IShellItemArray, SHGetKnownFolderPath, SHStrDupW,
    ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECS_ENABLED, ECS_HIDDEN, FOLDERID_LocalAppData, KF_FLAG_DEFAULT,
    SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND};
use uuid::Uuid;

static OBJECT_COUNT: AtomicIsize = AtomicIsize::new(0);
static SERVER_LOCKS: AtomicIsize = AtomicIsize::new(0);
const PARENT_TITLE: PCWSTR = w!("Hugging Face Drive");
const PARENT_CLSID: GUID = GUID::from_u128(0x3071d4e75a8643568bcecbb4e4c76734);

fn increment() {
    OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn decrement() {
    OBJECT_COUNT.fetch_sub(1, Ordering::Relaxed);
}

fn wide_to_string(pointer: PWSTR) -> Result<String, String> {
    if pointer.is_null() {
        return Err("null wide string".to_owned());
    }
    let mut length = 0usize;
    unsafe {
        while length < MAX_PATH_CHARS {
            if *pointer.0.add(length) == 0 {
                return String::from_utf16(std::slice::from_raw_parts(pointer.0, length))
                    .map_err(|_| "invalid UTF-16".to_owned());
            }
            length += 1;
        }
    }
    Err("wide string exceeds the Windows bound".to_owned())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn shell_directory() -> Result<PathBuf, String> {
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
        .map_err(|_| "known-folder lookup failed".to_owned())?;
    let path = wide_to_string(raw);
    unsafe { CoTaskMemFree(Some(raw.0 as *const core::ffi::c_void)) };
    let path = path?;
    if path.is_empty() {
        return Err("LocalAppData is unavailable".to_owned());
    }
    Ok(Path::new(&path).join("HFDrive").join("shell"))
}

fn requests_directory() -> Result<PathBuf, String> {
    Ok(shell_directory()?.join("requests"))
}

fn load_targets_from_local_cache() -> Vec<ImportTarget> {
    let Ok(path) = shell_directory() else { return Vec::new(); };
    let path = path.join("import-targets.json");
    let Ok(file) = std::fs::File::open(&path) else { return Vec::new(); };
    let Ok(metadata) = file.metadata() else { return Vec::new(); };
    if !metadata.is_file() || metadata.len() > MAX_JSON_BYTES {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if file.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes).is_err()
        || bytes.len() as u64 > MAX_JSON_BYTES
    {
        return Vec::new();
    }
    parse_targets(&bytes).unwrap_or_default()
}

fn write_request_file_atomic(directory: &Path, uuid: Uuid, json: &str) -> Result<(), String> {
    if json.is_empty() || json.len() as u64 > MAX_JSON_BYTES {
        return Err("request payload exceeds 1 MiB".to_owned());
    }
    let temporary = directory.join(format!("{uuid}.tmp"));
    let final_path = directory.join(format!("{uuid}.json"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    let write_result = file.write_all(json.as_bytes()).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(temporary);
        return Err(error.to_string());
    }
    let temporary_wide = wide(&temporary.to_string_lossy());
    let final_wide = wide(&final_path.to_string_lossy());
    let result = unsafe { MoveFileExW(PCWSTR(temporary_wide.as_ptr()), PCWSTR(final_wide.as_ptr()), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
        return Err("could not publish the import request".to_owned());
    }
    Ok(())
}

fn collect_paths(items: &IShellItemArray) -> WinResult<Vec<String>> {
    let count = unsafe { items.GetCount() }?;
    if count == 0 || count as usize > MAX_SOURCES {
        return Err(Error::from_hresult(E_INVALIDARG));
    }
    let mut sources = Vec::with_capacity(count as usize);
    for index in 0..count {
        let item = unsafe { items.GetItemAt(index) }?;
        let raw = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }?;
        let path = wide_to_string(raw);
        unsafe { CoTaskMemFree(Some(raw.0 as *const core::ffi::c_void)) };
        sources.push(path.map_err(|_| Error::from_hresult(E_INVALIDARG))?);
    }
    Ok(sources)
}

fn packaged_cli_path() -> Result<PathBuf, String> {
    let mut module = HMODULE(std::ptr::null_mut());
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(packaged_cli_path as *const () as *const u16),
            &mut module,
        )
    }
    .map_err(|_| "could not locate the packaged shell module".to_owned())?;
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetModuleFileNameW(Some(module), &mut buffer) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("could not locate the packaged shell module".to_owned());
    }
    buffer.truncate(length as usize);
    let module = String::from_utf16(&buffer).map_err(|_| "invalid module path".to_owned())?;
    let mut directory = PathBuf::from(module);
    if !directory.pop() {
        return Err("could not locate the packaged CLI".to_owned());
    }
    for _ in 0..4 {
        let candidate = directory.join("cli").join("hfdrive.exe");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if !directory.pop() {
            break;
        }
    }
    Err("packaged cli/hfdrive.exe was not found".to_owned())
}

fn launch_import_request(cli: &Path, operation_id: Uuid) -> Result<(), String> {
    let command = format!("\"{}\" import --request {}", cli.display(), operation_id);
    let mut command_wide = wide(&command);
    let application = wide(&cli.to_string_lossy());
    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process = PROCESS_INFORMATION::default();
    let result = unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_wide.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &mut startup,
            &mut process,
        )
    };
    if result.is_err() {
        return Err("could not start the packaged CLI".to_owned());
    }
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(process.hThread);
        let _ = windows::Win32::Foundation::CloseHandle(process.hProcess);
    }
    Ok(())
}

fn show_error(message: &str) {
    let message = wide(message);
    let caption = wide("Hugging Face Drive");
    unsafe {
        let _ = MessageBoxW(
            Some(windows::Win32::Foundation::HWND(std::ptr::null_mut())),
            PCWSTR(message.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
    }
}

#[windows::core::implement(IExplorerCommand)]
struct ParentCommand {
    targets: Vec<ImportTarget>,
}

impl ParentCommand {
    fn new(targets: Vec<ImportTarget>) -> Self {
        increment();
        Self { targets }
    }
}

impl Drop for ParentCommand {
    fn drop(&mut self) {
        decrement();
    }
}

#[windows::core::implement(IExplorerCommand)]
struct ChildCommand {
    target: ImportTarget,
}

impl ChildCommand {
    fn new(target: ImportTarget) -> Self {
        increment();
        Self { target }
    }
}

impl Drop for ChildCommand {
    fn drop(&mut self) {
        decrement();
    }
}

#[windows::core::implement(IEnumExplorerCommand)]
struct CommandEnumerator {
    targets: Vec<ImportTarget>,
    position: Cell<usize>,
}

impl CommandEnumerator {
    fn new(targets: Vec<ImportTarget>) -> Self {
        increment();
        Self { targets, position: Cell::new(0) }
    }
}

impl Drop for CommandEnumerator {
    fn drop(&mut self) {
        decrement();
    }
}

#[windows::core::implement(IClassFactory)]
struct ClassFactory;

impl ClassFactory {
    fn new() -> Self {
        increment();
        Self
    }
}

impl Drop for ClassFactory {
    fn drop(&mut self) {
        decrement();
    }
}

impl IExplorerCommand_Impl for ParentCommand_Impl {
    fn GetTitle(&self, _items: Ref<IShellItemArray>) -> WinResult<PWSTR> {
        unsafe { SHStrDupW(PARENT_TITLE) }
    }

    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> WinResult<PWSTR> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> WinResult<PWSTR> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetCanonicalName(&self) -> WinResult<GUID> {
        Ok(PARENT_CLSID)
    }

    fn GetState(&self, _items: Ref<IShellItemArray>, _slow: windows_core::BOOL) -> WinResult<u32> {
        Ok(if self.targets.is_empty() { ECS_HIDDEN.0 as u32 } else { ECS_ENABLED.0 as u32 })
    }

    fn Invoke(&self, _items: Ref<IShellItemArray>, _context: Ref<IBindCtx>) -> WinResult<()> {
        Err(Error::from_hresult(windows::Win32::Foundation::E_FAIL))
    }

    fn GetFlags(&self) -> WinResult<u32> {
        Ok(ECF_HASSUBCOMMANDS.0 as u32)
    }

    fn EnumSubCommands(&self) -> WinResult<IEnumExplorerCommand> {
        if self.targets.is_empty() {
            return Err(Error::from_hresult(windows::Win32::Foundation::E_FAIL));
        }
        Ok(CommandEnumerator::new(self.targets.clone()).into())
    }
}

impl IExplorerCommand_Impl for ChildCommand_Impl {
    fn GetTitle(&self, _items: Ref<IShellItemArray>) -> WinResult<PWSTR> {
        unsafe { SHStrDupW(PCWSTR(wide(&child_title(&self.target)).as_ptr())) }
    }

    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> WinResult<PWSTR> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> WinResult<PWSTR> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetCanonicalName(&self) -> WinResult<GUID> {
        Ok(GUID::zeroed())
    }

    fn GetState(&self, _items: Ref<IShellItemArray>, _slow: windows_core::BOOL) -> WinResult<u32> {
        Ok(ECS_ENABLED.0 as u32)
    }

    fn Invoke(&self, items: Ref<IShellItemArray>, _context: Ref<IBindCtx>) -> WinResult<()> {
        let items = items.ok()?;
        let sources = collect_paths(items).map_err(|error| {
            show_error("HF Drive could not read the selected items. No import was started.");
            error
        })?;
        let operation_id = Uuid::new_v4();
        let import_id = Uuid::new_v4();
        let json = build_request_json(operation_id, import_id, &self.target, &sources)
            .map_err(|error| {
                show_error(&error);
                Error::from_hresult(E_INVALIDARG)
            })?;
        let directory = requests_directory().map_err(|error| {
            show_error(&error);
            Error::from_hresult(E_INVALIDARG)
        })?;
        std::fs::create_dir_all(&directory).map_err(|error| {
            show_error(&error.to_string());
            Error::from_hresult(E_INVALIDARG)
        })?;
        write_request_file_atomic(&directory, operation_id, &json).map_err(|error| {
            show_error(&error);
            Error::from_hresult(E_INVALIDARG)
        })?;
        let cli = packaged_cli_path().map_err(|error| {
            show_error(&error);
            Error::from_hresult(E_INVALIDARG)
        })?;
        launch_import_request(&cli, operation_id).map_err(|error| {
            show_error(&error);
            Error::from_hresult(E_INVALIDARG)
        })
    }

    fn GetFlags(&self) -> WinResult<u32> {
        Ok(ECF_DEFAULT.0 as u32)
    }

    fn EnumSubCommands(&self) -> WinResult<IEnumExplorerCommand> {
        Err(Error::from_hresult(E_NOTIMPL))
    }
}

impl IEnumExplorerCommand_Impl for CommandEnumerator_Impl {
    fn Next(&self, celt: u32, commands: *mut Option<IExplorerCommand>, fetched: *mut u32) -> windows::core::HRESULT {
        if commands.is_null() {
            return E_POINTER;
        }
        if !fetched.is_null() {
            unsafe { *fetched = 0 };
        }
        let mut count = 0usize;
        while count < celt as usize && self.position.get() < self.targets.len() {
            let child = ChildCommand::new(self.targets[self.position.get()].clone());
            unsafe { commands.add(count).write(Some(child.into())) };
            self.position.set(self.position.get() + 1);
            count += 1;
        }
        if !fetched.is_null() {
            unsafe { *fetched = count as u32 };
        }
        if count == celt as usize { ERROR_SUCCESS.into() } else { windows::Win32::Foundation::S_FALSE.into() }
    }

    fn Skip(&self, celt: u32) -> WinResult<()> {
        let remaining = self.targets.len().saturating_sub(self.position.get());
        let skipped = (celt as usize).min(remaining);
        self.position.set(self.position.get() + skipped);
        if skipped == celt as usize {
            Ok(())
        } else {
            Err(Error::from_hresult(windows::Win32::Foundation::S_FALSE))
        }
    }

    fn Reset(&self) -> WinResult<()> {
        self.position.set(0);
        Ok(())
    }

    fn Clone(&self) -> WinResult<IEnumExplorerCommand> {
        let clone = CommandEnumerator::new(self.targets.clone());
        clone.position.set(self.position.get());
        Ok(clone.into())
    }
}

impl IClassFactory_Impl for ClassFactory_Impl {
    fn CreateInstance(&self, outer: Ref<windows::core::IUnknown>, riid: *const GUID, object: *mut *mut core::ffi::c_void) -> WinResult<()> {
        if object.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }
        unsafe { *object = std::ptr::null_mut() };
        if !outer.is_null() {
            return Err(Error::from_hresult(CLASS_E_NOAGGREGATION));
        }
        if riid.is_null() || unsafe { *riid != IExplorerCommand::IID && *riid != windows::core::IUnknown::IID } {
            return Err(Error::from_hresult(windows::Win32::Foundation::E_NOINTERFACE));
        }
        let command = ParentCommand::new(load_targets_from_local_cache());
        let interface: IExplorerCommand = command.into();
        unsafe { *object = interface.into_raw() };
        Ok(())
    }

    fn LockServer(&self, lock: windows_core::BOOL) -> WinResult<()> {
        if lock.as_bool() {
            SERVER_LOCKS.fetch_add(1, Ordering::Relaxed);
        } else {
            SERVER_LOCKS.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    class: *const GUID,
    iid: *const GUID,
    object: *mut *mut core::ffi::c_void,
) -> windows::core::HRESULT {
    if object.is_null() {
        return E_POINTER;
    }
    unsafe { *object = std::ptr::null_mut() };
    if class.is_null() || unsafe { *class != PARENT_CLSID } {
        return windows::Win32::Foundation::CLASS_E_CLASSNOTAVAILABLE;
    }
    if iid.is_null() {
        return E_POINTER;
    }
    if unsafe { *iid != IClassFactory::IID && *iid != windows::core::IUnknown::IID } {
        return windows::Win32::Foundation::E_NOINTERFACE;
    }
    let factory = ClassFactory::new();
    let interface: IClassFactory = factory.into();
    unsafe { *object = interface.into_raw() };
    ERROR_SUCCESS.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllCanUnloadNow() -> windows::core::HRESULT {
    if OBJECT_COUNT.load(Ordering::Relaxed) == 0 && SERVER_LOCKS.load(Ordering::Relaxed) == 0 {
        ERROR_SUCCESS.into()
    } else {
        windows::Win32::Foundation::S_FALSE.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_protocol::{OwnerKind, Visibility};

    fn target() -> ImportTarget {
        ImportTarget {
            owner_kind: OwnerKind::Personal,
            owner_id: "owner".to_owned(),
            owner_namespace: "alice".to_owned(),
            bucket_id: "bucket".to_owned(),
            bucket_name: "data".to_owned(),
            visibility: Visibility::Private,
        }
    }

    #[test]
    fn request_directory_is_under_hfdrive_shell() {
        let directory = requests_directory().unwrap();
        assert!(directory.ends_with(Path::new("HFDrive").join("shell").join("requests").as_path()));
    }

    #[test]
    fn request_creation_never_removes_a_preexisting_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let temporary = directory.path().join(format!("{id}.tmp"));
        std::fs::write(&temporary, "keep").unwrap();
        assert!(write_request_file_atomic(directory.path(), id, "{}").is_err());
        assert_eq!(std::fs::read_to_string(&temporary).unwrap(), "keep");
        assert!(!directory.path().join(format!("{id}.json")).exists());

        std::fs::remove_file(&temporary).unwrap();
        write_request_file_atomic(directory.path(), id, "{}").unwrap();
        assert_eq!(std::fs::read_to_string(directory.path().join(format!("{id}.json"))).unwrap(), "{}");
        assert!(!temporary.exists());
    }

    #[test]
    fn enum_clone_and_failed_factory_requests_balance_live_objects() {
        let enumerator: IEnumExplorerCommand = CommandEnumerator::new(vec![target(), target()]).into();
        let raw_skip = |command: &IEnumExplorerCommand, count| unsafe {
            (Interface::vtable(command).Skip)(Interface::as_raw(command), count)
        };
        assert_eq!(raw_skip(&enumerator, 1), ERROR_SUCCESS.into());
        let clone = unsafe { enumerator.Clone() }.unwrap();
        assert_eq!(raw_skip(&enumerator, 1), ERROR_SUCCESS.into());
        assert_eq!(raw_skip(&clone, 1), ERROR_SUCCESS.into());
        assert_eq!(raw_skip(&clone, 1), windows::Win32::Foundation::S_FALSE.into());
        unsafe { clone.Reset() }.unwrap();
        let mut commands = [None, None];
        let mut fetched = 0;
        assert_eq!(unsafe { clone.Next(&mut commands, Some(&mut fetched)) }, ERROR_SUCCESS.into());
        assert_eq!(fetched, 2);
        drop(commands);
        drop(clone);
        drop(enumerator);

        let mut object = std::ptr::dangling_mut::<core::ffi::c_void>();
        let unsupported = GUID::zeroed();
        assert_eq!(unsafe { DllGetClassObject(&PARENT_CLSID, &unsupported, &mut object) }, windows::Win32::Foundation::E_NOINTERFACE);
        assert!(object.is_null());
        assert_eq!(unsafe { DllCanUnloadNow() }, ERROR_SUCCESS.into());
    }
}
