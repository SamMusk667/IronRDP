//! Server side of the RDPDR static channel, for drive redirection ([MS-RDPEFS]).
//!
//! [`RdpdrServer`] runs the initialisation the client expects (Server Announce, capability exchange,
//! Client ID Confirm, User Logged On), tells a [`RdpdrServerHandler`] which drives the client shares
//! or stops sharing, and declines every other kind of device. [`RdpdrHandle`] sends the device I/O
//! requests that open, list, read, write, rename and delete the client's files; an [`IoRouter`] hands
//! each completion back to the request waiting for it, and every request gives up after a timeout.
//!
//! The channel only uses `ironrdp-rdpdr` for the wire types. Adapted from macrdp
//! (<https://github.com/clintcan/macrdp>), Copyright (c) 2026 Clint Christopher Canada, MIT OR
//! Apache-2.0.
//!
//! [MS-RDPEFS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/34d9de58-b2b5-40b6-b970-f82d4603bdb5

use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ironrdp_core::{ReadCursor, impl_as_any};
use ironrdp_pdu::gcc::ChannelName;
use ironrdp_pdu::{PduResult, decode_err};
pub use ironrdp_rdpdr::pdu::efs::{FileAttributes, NtStatus};
use ironrdp_rdpdr::pdu::efs::{
    Boolean, Capabilities, FileBasicInformation, ClientDeviceListAnnounce, ClientDeviceListRemove, ClientDriveQueryDirectoryResponse,
    ClientDriveQueryInformationResponse, ClientNameRequest, CoreCapability, CoreCapabilityKind, CreateDisposition,
    CreateOptions, DesiredAccess, DeviceAnnounceHeader, DeviceCloseRequest, DeviceCreateRequest, DeviceCreateResponse,
    DeviceIoRequest, DeviceIoResponse, DeviceReadRequest, DeviceReadResponse, DeviceType, DeviceWriteRequest,
    DeviceWriteResponse, FileDispositionInformation, FileEndOfFileInformation, FileInformationClass,
    FileInformationClassLevel, FileRenameInformation, MajorFunction, MinorFunction, ServerDeviceAnnounceResponse,
    ServerDriveIoRequest, ServerDriveQueryDirectoryRequest, ServerDriveQueryInformationRequest,
    ServerDriveSetInformationRequest, SharedAccess, VERSION_MAJOR, VERSION_MINOR_12, VersionAndIdPdu,
    VersionAndIdPduKind,
};
use ironrdp_rdpdr::pdu::{PacketId, RdpdrPdu, SharedHeader};
use ironrdp_svc::{CompressionCondition, SvcMessage, SvcProcessor, SvcServerProcessor};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::ServerEvent;

/// How long a request waits for the client's answer by default.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on the file handles kept open per connection. Reads and writes of one file reuse its
/// handle; the least recently used one is closed once more files than this are in use.
const MAX_OPEN_HANDLES: usize = 16;

/// A drive the client shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedDrive {
    pub device_id: u32,
    /// The drive's full name, such as `C` or `Documents`: DeviceData when the client sent it,
    /// otherwise PreferredDosName, which holds at most eight characters.
    pub name: String,
}

impl AnnouncedDrive {
    fn from_announce(device: &DeviceAnnounceHeader) -> Self {
        let name = drive_name(device.device_data())
            .unwrap_or_else(|| device.preferred_dos_name().trim_end_matches(':').to_owned());
        Self {
            device_id: device.device_id(),
            name,
        }
    }
}

/// Reads a drive's full name from DeviceData. MS-RDPEFS 2.2.3.1 asks for a null-terminated UTF-16
/// string, but FreeRDP and IronRDP's client send 8-bit characters with a single null terminator. Only
/// UTF-16 ends with two zero bytes at an even offset, unless the 8-bit name is empty.
fn drive_name(data: &[u8]) -> Option<String> {
    let utf16 = data.len() >= 4 && data.len().is_multiple_of(2) && data.ends_with(&[0, 0]);
    let name = if utf16 {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|&unit| unit != 0)
            .collect();
        String::from_utf16(&units).ok()?
    } else {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).into_owned()
    };
    let name = name.trim().trim_end_matches(':').to_owned();
    if name.is_empty() || name.chars().any(char::is_control) {
        None
    } else {
        Some(name)
    }
}

/// What the server does with the drives a client shares.
pub trait RdpdrServerHandler: Send + fmt::Debug {
    /// Hands over the handle for reading and writing the client's files. Called once, before the
    /// channel starts.
    fn set_handle(&mut self, _handle: RdpdrHandle) {}

    /// The client's computer name, from the Client Name Request.
    fn on_client_name(&mut self, _name: &str) {}

    /// The client shares these drives. A client may announce a drive it announced before.
    fn on_drives_announced(&mut self, drives: &[AnnouncedDrive]);

    /// The client no longer shares the drives with these device IDs.
    fn on_drives_removed(&mut self, _device_ids: &[u32]) {}
}

/// Builds the backend of the RDPDR channel for each connection, in the manner of
/// [`SoundServerFactory`] and [`CliprdrServerFactory`].
///
/// [`SoundServerFactory`]: crate::SoundServerFactory
/// [`CliprdrServerFactory`]: crate::CliprdrServerFactory
pub trait RdpdrServerFactory: Send {
    fn build_backend(&self) -> Box<dyn RdpdrServerHandler>;
}

/// RDPDR messages that the connection's event loop writes to the channel.
#[derive(Debug)]
pub enum RdpdrServerMessage {
    SendMessages(Vec<SvcMessage>),
}

/// Why a request to the client failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpdrError {
    /// The client answered with a failure status.
    Status { op: &'static str, status: NtStatus },
    /// The client did not answer within the request timeout.
    Timeout { op: &'static str },
    /// The channel closed, because the connection ended.
    Closed,
    /// The client's answer could not be decoded.
    Malformed { op: &'static str, reason: String },
}

impl fmt::Display for RdpdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { op, status } => write!(f, "RDPDR {op} failed with {status:?}"),
            Self::Timeout { op } => write!(f, "RDPDR {op}: the client did not answer in time"),
            Self::Closed => write!(f, "RDPDR channel closed"),
            Self::Malformed { op, reason } => write!(f, "RDPDR {op}: undecodable answer: {reason}"),
        }
    }
}

impl core::error::Error for RdpdrError {}

pub type RdpdrResult<T> = Result<T, RdpdrError>;

/// A file's size, attributes and times, the times as FILETIMEs: 100-nanosecond intervals since
/// 1601-01-01 UTC.
#[derive(Debug, Clone, PartialEq)]
pub struct FileInfo {
    pub size: u64,
    pub attributes: FileAttributes,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
}

impl FileInfo {
    pub fn is_dir(&self) -> bool {
        self.attributes.contains(FileAttributes::FILE_ATTRIBUTE_DIRECTORY)
    }

    pub fn is_read_only(&self) -> bool {
        self.attributes.contains(FileAttributes::FILE_ATTRIBUTE_READONLY)
    }
}

/// What [`RdpdrHandle::create_file`] does when the file exists already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMode {
    /// Fail with STATUS_OBJECT_NAME_COLLISION.
    Exclusive,
    /// Open it as it is.
    Open,
    /// Empty it.
    Truncate,
}

/// An entry of a directory listing.
#[derive(Debug, Clone, PartialEq)]
pub struct DirEntry {
    /// The entry's name, without its directory.
    pub name: String,
    pub info: FileInfo,
}

/// Hands each device I/O completion to the request waiting for it, by completion ID.
#[derive(Clone, Default)]
struct IoRouter {
    inner: Arc<IoRouterInner>,
}

#[derive(Default)]
struct IoRouterInner {
    next_id: AtomicU32,
    /// `None` once the channel has closed: requests then fail at once.
    pending: Mutex<Option<HashMap<u32, oneshot::Sender<Vec<u8>>>>>,
}

impl IoRouter {
    fn new() -> Self {
        let router = Self::default();
        *router.pending() = Some(HashMap::new());
        router
    }

    fn pending(&self) -> MutexGuard<'_, Option<HashMap<u32, oneshot::Sender<Vec<u8>>>>> {
        // A panic while the lock was held cannot leave the map inconsistent.
        self.inner.pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Allocates a completion ID and the receiver of its completion's body.
    fn register(&self) -> RdpdrResult<(u32, oneshot::Receiver<Vec<u8>>)> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending().as_mut().ok_or(RdpdrError::Closed)?.insert(id, tx);
        Ok((id, rx))
    }

    /// Delivers a completion's body, which starts with its DeviceIoResponse.
    fn deliver(&self, completion_id: u32, body: Vec<u8>) {
        let waiter = self.pending().as_mut().and_then(|pending| pending.remove(&completion_id));
        match waiter {
            Some(tx) => {
                let _ = tx.send(body);
            }
            None => debug!(completion_id, "RDPDR completion nobody waits for (timed out?)"),
        }
    }

    fn forget(&self, completion_id: u32) {
        if let Some(pending) = self.pending().as_mut() {
            pending.remove(&completion_id);
        }
    }

    /// Fails every waiting request, and every later one.
    fn close(&self) {
        self.pending().take();
    }
}

/// Which access a cached handle was opened with: a file can be open for reading and for writing at
/// once, and a read-only file cannot be opened for writing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum AccessKind {
    Read,
    Write,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct HandleKey {
    device_id: u32,
    path: String,
    kind: AccessKind,
}

struct CachedHandle {
    file_id: u32,
    last_used: u64,
}

/// Open file handles, least recently used first out. Consecutive reads or writes of a file reuse one
/// handle instead of an open and a close for every chunk, so a large transfer costs one round trip
/// per chunk instead of three.
#[derive(Default)]
struct HandleCache {
    map: Mutex<HashMap<HandleKey, CachedHandle>>,
    tick: AtomicU64,
}

impl HandleCache {
    fn map(&self) -> MutexGuard<'_, HashMap<HandleKey, CachedHandle>> {
        self.map.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn stamp(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }
}

/// Sends device I/O requests to the client. Clones share the channel, the pending requests and the
/// open handles.
///
/// Paths are relative to the drive's root, with backslashes: `\` is the root and `\docs\a.txt` a file
/// in the folder `docs`.
#[derive(Clone)]
pub struct RdpdrHandle {
    sender: mpsc::UnboundedSender<ServerEvent>,
    router: IoRouter,
    cache: Arc<HandleCache>,
    timeout: Duration,
}

impl fmt::Debug for RdpdrHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpdrHandle")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl RdpdrHandle {
    fn new(sender: mpsc::UnboundedSender<ServerEvent>, router: IoRouter) -> Self {
        Self {
            sender,
            router,
            cache: Arc::new(HandleCache::default()),
            timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Returns a handle whose requests give up after `timeout` instead of [`DEFAULT_REQUEST_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The size, attributes and times of the file or folder at `path`.
    pub async fn stat(&self, device_id: u32, path: &str) -> RdpdrResult<FileInfo> {
        let file_id = self
            .open(
                device_id,
                path,
                DesiredAccess::FILE_READ_ATTRIBUTES | DesiredAccess::SYNCHRONIZE,
                CreateDisposition::FILE_OPEN,
                CreateOptions::empty(),
            )
            .await?;
        let info = self.query_info(device_id, file_id).await;
        self.close(device_id, file_id).await;
        info
    }

    /// The entries of the folder at `dir`, without `.` and `..`. The client returns one entry per
    /// request, so a listing costs a round trip for each entry.
    pub async fn list_dir(&self, device_id: u32, dir: &str) -> RdpdrResult<Vec<DirEntry>> {
        let file_id = self
            .open(
                device_id,
                dir,
                DesiredAccess::FILE_READ_DATA_OR_FILE_LIST_DIRECTORY
                    | DesiredAccess::FILE_READ_ATTRIBUTES
                    | DesiredAccess::SYNCHRONIZE,
                CreateDisposition::FILE_OPEN,
                CreateOptions::FILE_DIRECTORY_FILE | CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT,
            )
            .await?;
        let entries = self.query_directory(device_id, file_id, dir).await;
        self.close(device_id, file_id).await;
        entries
    }

    /// Reads up to `length` bytes at `offset` of the file at `path`, through a cached handle. Fewer
    /// bytes than asked for mean the end of the file.
    pub async fn read_file(&self, device_id: u32, path: &str, offset: u64, length: u32) -> RdpdrResult<Vec<u8>> {
        let file_id = self.acquire(device_id, path, AccessKind::Read).await?;
        let result = self.read(device_id, file_id, offset, length).await;
        if result.is_err() {
            // The handle may have gone stale; the next read opens a new one.
            self.invalidate(device_id, path, AccessKind::Read);
        }
        result
    }

    /// Writes `data` at `offset` of the existing file at `path`, through a cached handle, and returns
    /// how many bytes the client wrote.
    pub async fn write_file(&self, device_id: u32, path: &str, offset: u64, data: &[u8]) -> RdpdrResult<u32> {
        let file_id = self.acquire(device_id, path, AccessKind::Write).await?;
        let result = self.write(device_id, file_id, offset, data).await;
        if result.is_err() {
            self.invalidate(device_id, path, AccessKind::Write);
        }
        result
    }

    /// Creates a file at `path`, or does what `mode` says with one that exists.
    pub async fn create_file(&self, device_id: u32, path: &str, mode: CreateMode) -> RdpdrResult<()> {
        let disposition = match mode {
            CreateMode::Exclusive => CreateDisposition::FILE_CREATE,
            CreateMode::Open => CreateDisposition::FILE_OPEN_IF,
            CreateMode::Truncate => CreateDisposition::FILE_OVERWRITE_IF,
        };
        // A file being emptied may be open for reading or writing through a cached handle, whose view
        // of it would be stale.
        if mode == CreateMode::Truncate {
            self.evict_path(device_id, path).await;
        }
        let file_id = self
            .open(
                device_id,
                path,
                file_write_access(),
                disposition,
                CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions::FILE_NON_DIRECTORY_FILE,
            )
            .await?;
        self.close(device_id, file_id).await;
        Ok(())
    }

    /// Creates a folder at `path`, failing if something exists there.
    pub async fn create_dir(&self, device_id: u32, path: &str) -> RdpdrResult<()> {
        let file_id = self
            .open(
                device_id,
                path,
                file_write_access(),
                CreateDisposition::FILE_CREATE,
                CreateOptions::FILE_DIRECTORY_FILE | CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT,
            )
            .await?;
        self.close(device_id, file_id).await;
        Ok(())
    }

    /// Deletes the file, or the empty folder, at `path`: it is opened for deletion, marked delete
    /// pending, and removed when the handle closes.
    pub async fn remove(&self, device_id: u32, path: &str, is_dir: bool) -> RdpdrResult<()> {
        // A handle still open would postpone the deletion until it closed.
        self.evict_path(device_id, path).await;
        let options = if is_dir {
            CreateOptions::FILE_DIRECTORY_FILE | CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            CreateOptions::FILE_NON_DIRECTORY_FILE | CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT
        };
        let file_id = self
            .open(
                device_id,
                path,
                DesiredAccess::DELETE | DesiredAccess::SYNCHRONIZE,
                CreateDisposition::FILE_OPEN,
                options,
            )
            .await?;
        let result = self
            .set_information(
                device_id,
                file_id,
                FileInformationClass::Disposition(FileDispositionInformation { delete_pending: 1 }),
            )
            .await;
        self.close(device_id, file_id).await;
        result
    }

    /// Renames or moves the file or folder at `from` to `to`, replacing what is at `to` if `replace`.
    pub async fn rename(&self, device_id: u32, from: &str, to: &str, replace: bool) -> RdpdrResult<()> {
        // A handle open on the source can block the rename, and one on the destination goes stale.
        self.evict_path(device_id, from).await;
        self.evict_path(device_id, to).await;
        let file_id = self
            .open(
                device_id,
                from,
                DesiredAccess::DELETE | DesiredAccess::SYNCHRONIZE,
                CreateDisposition::FILE_OPEN,
                CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT,
            )
            .await?;
        let result = self
            .set_information(
                device_id,
                file_id,
                FileInformationClass::Rename(FileRenameInformation {
                    replace_if_exists: if replace { Boolean::True } else { Boolean::False },
                    file_name: to.to_owned(),
                }),
            )
            .await;
        self.close(device_id, file_id).await;
        result
    }

    /// Truncates or extends the file at `path` to `size` bytes.
    pub async fn set_len(&self, device_id: u32, path: &str, size: u64) -> RdpdrResult<()> {
        let file_id = self
            .open(
                device_id,
                path,
                file_write_access(),
                CreateDisposition::FILE_OPEN,
                CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions::FILE_NON_DIRECTORY_FILE,
            )
            .await?;
        let end_of_file = i64::try_from(size).unwrap_or(i64::MAX);
        let result = self
            .set_information(
                device_id,
                file_id,
                FileInformationClass::EndOfFile(FileEndOfFileInformation { end_of_file }),
            )
            .await;
        self.close(device_id, file_id).await;
        result
    }

    /// Sets the last access and last write times of the file or folder at `path`, as FILETIMEs;
    /// `None` leaves a time as it is.
    pub async fn set_times(
        &self,
        device_id: u32,
        path: &str,
        last_access_time: Option<i64>,
        last_write_time: Option<i64>,
    ) -> RdpdrResult<()> {
        let file_id = self
            .open(
                device_id,
                path,
                DesiredAccess::FILE_WRITE_ATTRIBUTES | DesiredAccess::SYNCHRONIZE,
                CreateDisposition::FILE_OPEN,
                CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT,
            )
            .await?;
        // Zero leaves a time, and the attributes, unchanged (MS-FSCC 2.4.7).
        let result = self
            .set_information(
                device_id,
                file_id,
                FileInformationClass::Basic(FileBasicInformation {
                    creation_time: 0,
                    last_access_time: last_access_time.unwrap_or(0),
                    last_write_time: last_write_time.unwrap_or(0),
                    change_time: 0,
                    file_attributes: FileAttributes::empty(),
                }),
            )
            .await;
        self.close(device_id, file_id).await;
        result
    }

    /// Closes the cached handles of `path`, so that the client sees the file as closed: before a
    /// deletion or a rename, or when the server is done with the file for now.
    pub async fn release(&self, device_id: u32, path: &str) {
        self.evict_path(device_id, path).await;
    }

    /// Forgets the cached handles of a drive the client no longer shares; they died with it.
    pub fn forget_device(&self, device_id: u32) {
        self.cache.map().retain(|key, _| key.device_id != device_id);
    }

    fn send(&self, request: ServerDriveIoRequest) -> RdpdrResult<()> {
        self.sender
            .send(ServerEvent::Rdpdr(RdpdrServerMessage::SendMessages(vec![SvcMessage::from(
                request,
            )])))
            .map_err(|_| RdpdrError::Closed)
    }

    /// Sends the request that `build` makes for a new completion ID and returns the body of its
    /// completion, or an error if none comes in time.
    async fn request(
        &self,
        op: &'static str,
        build: impl FnOnce(u32) -> ServerDriveIoRequest,
    ) -> RdpdrResult<Vec<u8>> {
        let (completion_id, rx) = self.router.register()?;
        if let Err(error) = self.send(build(completion_id)) {
            self.router.forget(completion_id);
            return Err(error);
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(body)) => Ok(body),
            Ok(Err(_)) => Err(RdpdrError::Closed),
            Err(_) => {
                self.router.forget(completion_id);
                warn!(op, timeout = ?self.timeout, "RDPDR request timed out");
                Err(RdpdrError::Timeout { op })
            }
        }
    }

    /// IRP_MJ_CREATE: opens or creates `path` and returns the client's file ID.
    async fn open(
        &self,
        device_id: u32,
        path: &str,
        desired_access: DesiredAccess,
        create_disposition: CreateDisposition,
        create_options: CreateOptions,
    ) -> RdpdrResult<u32> {
        const OP: &str = "create";
        let body = self
            .request(OP, |completion_id| {
                ServerDriveIoRequest::ServerCreateDriveRequest(DeviceCreateRequest {
                    device_io_request: io_request(device_id, 0, completion_id, MajorFunction::Create),
                    desired_access,
                    allocation_size: 0,
                    file_attributes: FileAttributes::empty(),
                    // Files the client's own programs hold open can still be opened; a narrower share
                    // mode ends in STATUS_SHARING_VIOLATION.
                    shared_access: SharedAccess::FILE_SHARE_READ
                        | SharedAccess::FILE_SHARE_WRITE
                        | SharedAccess::FILE_SHARE_DELETE,
                    create_disposition,
                    create_options,
                    path: path.to_owned(),
                })
            })
            .await?;
        let response = DeviceCreateResponse::decode(&mut ReadCursor::new(&body)).map_err(|e| malformed(OP, &e))?;
        check(OP, &response.device_io_reply)?;
        Ok(response.file_id)
    }

    async fn close(&self, device_id: u32, file_id: u32) {
        let result = self
            .request("close", |completion_id| {
                ServerDriveIoRequest::DeviceCloseRequest(DeviceCloseRequest {
                    device_io_request: io_request(device_id, file_id, completion_id, MajorFunction::Close),
                })
            })
            .await;
        if let Err(error) = result {
            debug!(%error, "RDPDR close failed");
        }
    }

    /// Closes a handle without waiting: for handles the cache lets go of.
    fn close_in_background(&self, device_id: u32, file_id: u32) {
        let this = self.clone();
        tokio::spawn(async move { this.close(device_id, file_id).await });
    }

    async fn read(&self, device_id: u32, file_id: u32, offset: u64, length: u32) -> RdpdrResult<Vec<u8>> {
        const OP: &str = "read";
        let body = self
            .request(OP, |completion_id| {
                ServerDriveIoRequest::DeviceReadRequest(DeviceReadRequest {
                    device_io_request: io_request(device_id, file_id, completion_id, MajorFunction::Read),
                    length,
                    offset,
                })
            })
            .await?;
        let response = DeviceReadResponse::decode(&mut ReadCursor::new(&body)).map_err(|e| malformed(OP, &e))?;
        check(OP, &response.device_io_reply)?;
        Ok(response.read_data)
    }

    async fn write(&self, device_id: u32, file_id: u32, offset: u64, data: &[u8]) -> RdpdrResult<u32> {
        const OP: &str = "write";
        let body = self
            .request(OP, |completion_id| {
                ServerDriveIoRequest::DeviceWriteRequest(DeviceWriteRequest {
                    device_io_request: io_request(device_id, file_id, completion_id, MajorFunction::Write),
                    offset,
                    write_data: data.to_vec(),
                })
            })
            .await?;
        let response = DeviceWriteResponse::decode(&mut ReadCursor::new(&body)).map_err(|e| malformed(OP, &e))?;
        check(OP, &response.device_io_reply)?;
        Ok(response.length)
    }

    async fn set_information(&self, device_id: u32, file_id: u32, set_buffer: FileInformationClass) -> RdpdrResult<()> {
        const OP: &str = "set information";
        let body = self
            .request(OP, |completion_id| {
                ServerDriveIoRequest::ServerDriveSetInformationRequest(ServerDriveSetInformationRequest {
                    device_io_request: io_request(device_id, file_id, completion_id, MajorFunction::SetInformation),
                    set_buffer,
                })
            })
            .await?;
        // Only the status matters: the rest of the response repeats the request's length.
        let response = DeviceIoResponse::decode(&mut ReadCursor::new(&body)).map_err(|e| malformed(OP, &e))?;
        check(OP, &response)
    }

    async fn query_information(
        &self,
        device_id: u32,
        file_id: u32,
        level: FileInformationClassLevel,
    ) -> RdpdrResult<FileInformationClass> {
        const OP: &str = "query information";
        let body = self
            .request(OP, |completion_id| {
                ServerDriveIoRequest::ServerDriveQueryInformationRequest(ServerDriveQueryInformationRequest {
                    device_io_request: io_request(device_id, file_id, completion_id, MajorFunction::QueryInformation),
                    file_info_class_lvl: level.clone(),
                })
            })
            .await?;
        let response = ClientDriveQueryInformationResponse::decode(&mut ReadCursor::new(&body), level)
            .map_err(|e| malformed(OP, &e))?;
        check(OP, &response.device_io_response)?;
        response.buffer.ok_or_else(|| RdpdrError::Malformed {
            op: OP,
            reason: "no information in a successful answer".to_owned(),
        })
    }

    async fn query_info(&self, device_id: u32, file_id: u32) -> RdpdrResult<FileInfo> {
        let basic = self
            .query_information(device_id, file_id, FileInformationClassLevel::FILE_BASIC_INFORMATION)
            .await?;
        let standard = self
            .query_information(device_id, file_id, FileInformationClassLevel::FILE_STANDARD_INFORMATION)
            .await?;
        match (basic, standard) {
            (FileInformationClass::Basic(basic), FileInformationClass::Standard(standard)) => {
                let mut attributes = basic.file_attributes;
                // Some clients leave the directory attribute out of FileBasicInformation.
                if standard.directory == Boolean::True {
                    attributes |= FileAttributes::FILE_ATTRIBUTE_DIRECTORY;
                }
                Ok(FileInfo {
                    size: u64::try_from(standard.end_of_file).unwrap_or(0),
                    attributes,
                    creation_time: basic.creation_time,
                    last_access_time: basic.last_access_time,
                    last_write_time: basic.last_write_time,
                    change_time: basic.change_time,
                })
            }
            _ => Err(RdpdrError::Malformed {
                op: "query information",
                reason: "an answer of another class than asked for".to_owned(),
            }),
        }
    }

    async fn query_directory(&self, device_id: u32, file_id: u32, dir: &str) -> RdpdrResult<Vec<DirEntry>> {
        const OP: &str = "query directory";
        let pattern = query_pattern(dir);
        let mut entries = Vec::new();
        let mut initial = true;
        loop {
            let body = self
                .request(OP, |completion_id| {
                    let mut header = io_request(device_id, file_id, completion_id, MajorFunction::DirectoryControl);
                    header.minor_function = MinorFunction::IRP_MN_QUERY_DIRECTORY;
                    ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(ServerDriveQueryDirectoryRequest {
                        device_io_request: header,
                        file_info_class_lvl: FileInformationClassLevel::FILE_DIRECTORY_INFORMATION,
                        initial_query: u8::from(initial),
                        // Later queries continue the enumeration and carry no path.
                        path: if initial { pattern.clone() } else { String::new() },
                    })
                })
                .await?;
            initial = false;
            let response = ClientDriveQueryDirectoryResponse::decode(
                &mut ReadCursor::new(&body),
                FileInformationClassLevel::FILE_DIRECTORY_INFORMATION,
            )
            .map_err(|e| malformed(OP, &e))?;
            let status = response.device_io_reply.io_status;
            if status == NtStatus::NO_MORE_FILES {
                break;
            }
            // An empty folder may answer the first query with STATUS_NO_SUCH_FILE.
            if status == NtStatus::NO_SUCH_FILE && entries.is_empty() {
                break;
            }
            check(OP, &response.device_io_reply)?;
            let Some(FileInformationClass::Directory(entry)) = response.buffer else {
                break;
            };
            if entry.file_name == "." || entry.file_name == ".." {
                continue;
            }
            entries.push(DirEntry {
                name: entry.file_name,
                info: FileInfo {
                    size: u64::try_from(entry.end_of_file).unwrap_or(0),
                    attributes: entry.file_attributes,
                    creation_time: entry.creation_time,
                    last_access_time: entry.last_access_time,
                    last_write_time: entry.last_write_time,
                    change_time: entry.change_time,
                },
            });
        }
        Ok(entries)
    }

    /// A cached handle for `path` opened for `kind`, opened and cached if there is none.
    async fn acquire(&self, device_id: u32, path: &str, kind: AccessKind) -> RdpdrResult<u32> {
        let key = HandleKey {
            device_id,
            path: path.to_owned(),
            kind,
        };
        if let Some(handle) = self.cache.map().get_mut(&key) {
            handle.last_used = self.cache.stamp();
            return Ok(handle.file_id);
        }
        let access = match kind {
            AccessKind::Read => file_read_access(),
            AccessKind::Write => file_write_access(),
        };
        let file_id = self
            .open(
                device_id,
                path,
                access,
                CreateDisposition::FILE_OPEN,
                CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions::FILE_NON_DIRECTORY_FILE,
            )
            .await?;

        let mut to_close = Vec::new();
        let file_id = {
            let mut map = self.cache.map();
            if let Some(handle) = map.get_mut(&key) {
                // Another request opened the same file meanwhile: use its handle and close ours.
                handle.last_used = self.cache.stamp();
                to_close.push((device_id, file_id));
                handle.file_id
            } else {
                map.insert(
                    key,
                    CachedHandle {
                        file_id,
                        last_used: self.cache.stamp(),
                    },
                );
                if map.len() > MAX_OPEN_HANDLES {
                    let oldest = map.iter().min_by_key(|(_, h)| h.last_used).map(|(k, _)| k.clone());
                    if let Some(evicted) = oldest.and_then(|k| map.remove(&k).map(|h| (k.device_id, h.file_id))) {
                        to_close.push(evicted);
                    }
                }
                file_id
            }
        };
        for (device_id, file_id) in to_close {
            self.close_in_background(device_id, file_id);
        }
        Ok(file_id)
    }

    /// Drops a cached handle after a failed request and closes it.
    fn invalidate(&self, device_id: u32, path: &str, kind: AccessKind) {
        let key = HandleKey {
            device_id,
            path: path.to_owned(),
            kind,
        };
        let file_id = self.cache.map().remove(&key).map(|h| h.file_id);
        if let Some(file_id) = file_id {
            self.close_in_background(device_id, file_id);
        }
    }

    /// Closes the cached handles of `path`, of both kinds, and waits for the client to confirm.
    async fn evict_path(&self, device_id: u32, path: &str) {
        let file_ids: Vec<u32> = {
            let mut map = self.cache.map();
            let keys: Vec<HandleKey> = map
                .keys()
                .filter(|k| k.device_id == device_id && k.path == path)
                .cloned()
                .collect();
            keys.iter().filter_map(|k| map.remove(k)).map(|h| h.file_id).collect()
        };
        for file_id in file_ids {
            self.close(device_id, file_id).await;
        }
    }
}

fn io_request(device_id: u32, file_id: u32, completion_id: u32, major_function: MajorFunction) -> DeviceIoRequest {
    DeviceIoRequest {
        device_id,
        file_id,
        completion_id,
        major_function,
        minor_function: MinorFunction::from(0),
    }
}

fn check(op: &'static str, response: &DeviceIoResponse) -> RdpdrResult<()> {
    if response.io_status == NtStatus::SUCCESS {
        Ok(())
    } else {
        Err(RdpdrError::Status {
            op,
            status: response.io_status,
        })
    }
}

fn malformed(op: &'static str, error: &impl fmt::Display) -> RdpdrError {
    RdpdrError::Malformed {
        op,
        reason: error.to_string(),
    }
}

/// What `CreateFile(GENERIC_READ)` expands to. mstsc honours the rights strictly: without SYNCHRONIZE
/// the synchronous read that follows fails with STATUS_ACCESS_DENIED, which FreeRDP lets pass.
fn file_read_access() -> DesiredAccess {
    DesiredAccess::FILE_READ_DATA_OR_FILE_LIST_DIRECTORY
        | DesiredAccess::FILE_READ_ATTRIBUTES
        | DesiredAccess::FILE_READ_EA
        | DesiredAccess::READ_CONTROL
        | DesiredAccess::SYNCHRONIZE
}

/// Read and write rights, so that a handle opened for writing can also be read.
fn file_write_access() -> DesiredAccess {
    file_read_access()
        | DesiredAccess::FILE_WRITE_DATA_OR_FILE_ADD_FILE
        | DesiredAccess::FILE_APPEND_DATA_OR_FILE_ADD_SUBDIRECTORY
        | DesiredAccess::FILE_WRITE_ATTRIBUTES
        | DesiredAccess::FILE_WRITE_EA
}

/// The search pattern of the first query of a folder: its path followed by `\*`.
fn query_pattern(dir: &str) -> String {
    if dir.is_empty() || dir == "\\" {
        "\\*".to_owned()
    } else if dir.ends_with('\\') {
        format!("{dir}*")
    } else {
        format!("{dir}\\*")
    }
}

/// The processor of the RDPDR static channel.
pub struct RdpdrServer {
    backend: Box<dyn RdpdrServerHandler>,
    handle: RdpdrHandle,
    /// The client ID the client chose, echoed back in the Server Client ID Confirm.
    client_id: u32,
}

impl fmt::Debug for RdpdrServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpdrServer")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl_as_any!(RdpdrServer);

impl RdpdrServer {
    /// Builds the processor for a connection whose server events go to `sender`, and hands the
    /// backend its [`RdpdrHandle`].
    pub fn new(mut backend: Box<dyn RdpdrServerHandler>, sender: mpsc::UnboundedSender<ServerEvent>) -> Self {
        let handle = RdpdrHandle::new(sender, IoRouter::new());
        backend.set_handle(handle.clone());
        Self {
            backend,
            handle,
            client_id: 1,
        }
    }

    /// The capabilities the server announces. A client keeps only the kinds of device the server
    /// announces too, so the drive capability has to be there.
    fn server_capabilities() -> CoreCapability {
        let mut capabilities = Capabilities::new();
        capabilities.add_drive();
        CoreCapability {
            capabilities: capabilities.clone_inner(),
            kind: CoreCapabilityKind::ServerCoreCapabilityRequest,
        }
    }

    fn version_and_id(&self, kind: VersionAndIdPduKind) -> RdpdrPdu {
        // Minor version 12, as Windows servers send. At 5 (RDP 5.1) clients announce all their devices
        // before logon and again after it.
        RdpdrPdu::VersionAndIdPdu(VersionAndIdPdu {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR_12,
            client_id: self.client_id,
            kind,
        })
    }

    fn devices_announced(&mut self, announce: &ClientDeviceListAnnounce) -> Vec<SvcMessage> {
        let mut drives = Vec::new();
        let mut replies = Vec::new();
        for device in &announce.device_list {
            let result_code = if device.device_type() == DeviceType::Filesystem {
                let drive = AnnouncedDrive::from_announce(device);
                info!(device_id = drive.device_id, name = %drive.name, "RDPDR: the client shares a drive");
                drives.push(drive);
                NtStatus::SUCCESS
            } else {
                debug!(device_id = device.device_id(), device_type = ?device.device_type(), "RDPDR: declining a device");
                NtStatus::NOT_SUPPORTED
            };
            replies.push(SvcMessage::from(RdpdrPdu::ServerDeviceAnnounceResponse(
                ServerDeviceAnnounceResponse {
                    device_id: device.device_id(),
                    result_code,
                },
            )));
        }
        if !drives.is_empty() {
            self.backend.on_drives_announced(&drives);
        }
        replies
    }
}

impl Drop for RdpdrServer {
    fn drop(&mut self) {
        // The connection is over: whatever still waits for the client never gets an answer.
        self.handle.router.close();
    }
}

impl SvcProcessor for RdpdrServer {
    fn channel_name(&self) -> ChannelName {
        ChannelName::from_static(b"rdpdr\0\0\0")
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        debug!("RDPDR: Server Announce Request");
        Ok(vec![SvcMessage::from(
            self.version_and_id(VersionAndIdPduKind::ServerAnnounceRequest),
        )])
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let header = SharedHeader::decode(&mut src).map_err(|e| decode_err!(e))?;

        match header.packet_id {
            PacketId::CoreClientidConfirm => {
                // The Client Announce Reply. The server answers with its capabilities and the Client
                // ID Confirm together (MS-RDPEFS 3.3.5.1): mstsc waits for the confirm before it sends
                // its capabilities, where FreeRDP does not.
                let reply = VersionAndIdPdu::decode(header, &mut src).map_err(|e| decode_err!(e))?;
                debug!(client_id = reply.client_id, "RDPDR: Client Announce Reply");
                self.client_id = reply.client_id;
                Ok(vec![
                    SvcMessage::from(RdpdrPdu::CoreCapability(Self::server_capabilities())),
                    SvcMessage::from(self.version_and_id(VersionAndIdPduKind::ServerClientIdConfirm)),
                ])
            }
            PacketId::CoreClientName => {
                let name = match ClientNameRequest::decode(&mut src).map_err(|e| decode_err!(e))? {
                    ClientNameRequest::Ascii(name) | ClientNameRequest::Unicode(name) => name,
                };
                debug!(%name, "RDPDR: Client Name");
                self.backend.on_client_name(&name);
                Ok(Vec::new())
            }
            PacketId::CoreClientCapability => {
                let _capabilities = CoreCapability::decode(header, &mut src).map_err(|e| decode_err!(e))?;
                // User Logged On asks the client to announce the devices it shares after logon, drives
                // among them.
                debug!("RDPDR: Client Capability Response");
                Ok(vec![SvcMessage::from(RdpdrPdu::UserLoggedon)])
            }
            PacketId::CoreDevicelistAnnounce => {
                let announce = ClientDeviceListAnnounce::decode(&mut src).map_err(|e| decode_err!(e))?;
                Ok(self.devices_announced(&announce))
            }
            PacketId::CoreDevicelistRemove => {
                let remove = ClientDeviceListRemove::decode(&mut src).map_err(|e| decode_err!(e))?;
                info!(device_ids = ?remove.device_list, "RDPDR: the client stops sharing devices");
                for &device_id in &remove.device_list {
                    self.handle.forget_device(device_id);
                }
                self.backend.on_drives_removed(&remove.device_list);
                Ok(Vec::new())
            }
            PacketId::CoreDeviceIoCompletion => {
                // The DeviceIoResponse at the front gives the completion ID; the waiting request
                // decodes the rest, whose layout depends on what it asked for.
                let body = src.remaining();
                match DeviceIoResponse::decode(&mut ReadCursor::new(body)) {
                    Ok(response) => self.handle.router.deliver(response.completion_id, body.to_vec()),
                    Err(error) => warn!(%error, "RDPDR: undecodable device I/O completion"),
                }
                Ok(Vec::new())
            }
            other => {
                debug!(packet_id = ?other, "RDPDR: ignoring a packet");
                Ok(Vec::new())
            }
        }
    }
}

impl SvcServerProcessor for RdpdrServer {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    #![allow(clippy::panic, reason = "tests")]

    use ironrdp_core::encode_vec;
    use ironrdp_rdpdr::pdu::efs::{
        ClientNameRequestUnicodeFlag, DeviceCloseResponse, FileDirectoryInformation,
        FileStandardInformation, Information,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct Recorded {
        handle: Option<RdpdrHandle>,
        client_name: Option<String>,
        announced: Vec<AnnouncedDrive>,
        removed: Vec<u32>,
    }

    #[derive(Debug, Clone, Default)]
    struct Recorder(Arc<Mutex<Recorded>>);

    impl RdpdrServerHandler for Recorder {
        fn set_handle(&mut self, handle: RdpdrHandle) {
            self.0.lock().unwrap().handle = Some(handle);
        }

        fn on_client_name(&mut self, name: &str) {
            self.0.lock().unwrap().client_name = Some(name.to_owned());
        }

        fn on_drives_announced(&mut self, drives: &[AnnouncedDrive]) {
            self.0.lock().unwrap().announced.extend_from_slice(drives);
        }

        fn on_drives_removed(&mut self, device_ids: &[u32]) {
            self.0.lock().unwrap().removed.extend_from_slice(device_ids);
        }
    }

    fn server() -> (RdpdrServer, Recorder, mpsc::UnboundedReceiver<ServerEvent>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let recorder = Recorder::default();
        (RdpdrServer::new(Box::new(recorder.clone()), sender), recorder, receiver)
    }

    fn bytes(message: &SvcMessage) -> Vec<u8> {
        message.encode_unframed_pdu().unwrap()
    }

    fn packet_id(message: &SvcMessage) -> PacketId {
        SharedHeader::decode(&mut ReadCursor::new(&bytes(message))).unwrap().packet_id
    }

    fn from_client(pdu: RdpdrPdu) -> Vec<u8> {
        encode_vec(&pdu).unwrap()
    }

    fn announce(devices: &[(u32, u32, &[u8; 8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x4472u16.to_le_bytes());
        out.extend_from_slice(&0x4441u16.to_le_bytes()); // PAKID_CORE_DEVICELIST_ANNOUNCE
        out.extend_from_slice(&u32::try_from(devices.len()).unwrap().to_le_bytes());
        for &(device_type, device_id, dos_name, data) in devices {
            out.extend_from_slice(&device_type.to_le_bytes());
            out.extend_from_slice(&device_id.to_le_bytes());
            out.extend_from_slice(dos_name);
            out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    /// The request the handle sent, decoded as a client decodes it.
    fn next_request(receiver: &mut mpsc::UnboundedReceiver<ServerEvent>) -> ServerDriveIoRequest {
        let Some(ServerEvent::Rdpdr(RdpdrServerMessage::SendMessages(messages))) = receiver.try_recv().ok() else {
            panic!("no RDPDR request was sent");
        };
        assert_eq!(messages.len(), 1);
        let bytes = bytes(&messages[0]);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(SharedHeader::decode(&mut src).unwrap().packet_id, PacketId::CoreDeviceIoRequest);
        let io = DeviceIoRequest::decode(&mut src).unwrap();
        ServerDriveIoRequest::decode(io, &mut src).unwrap()
    }

    fn completion_id(request: &ServerDriveIoRequest) -> u32 {
        match request {
            ServerDriveIoRequest::ServerCreateDriveRequest(r) => r.device_io_request.completion_id,
            ServerDriveIoRequest::ServerDriveQueryInformationRequest(r) => r.device_io_request.completion_id,
            ServerDriveIoRequest::DeviceCloseRequest(r) => r.device_io_request.completion_id,
            ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(r) => r.device_io_request.completion_id,
            ServerDriveIoRequest::DeviceReadRequest(r) => r.device_io_request.completion_id,
            ServerDriveIoRequest::DeviceWriteRequest(r) => r.device_io_request.completion_id,
            ServerDriveIoRequest::ServerDriveSetInformationRequest(r) => r.device_io_request.completion_id,
            other => panic!("unexpected request {other:?}"),
        }
    }

    fn response(completion_id: u32, io_status: NtStatus) -> DeviceIoResponse {
        DeviceIoResponse {
            device_id: 1,
            completion_id,
            io_status,
        }
    }

    #[test]
    fn handshake_follows_what_mstsc_expects() {
        let (mut server, recorder, _receiver) = server();

        let start = server.start().unwrap();
        assert_eq!(start.len(), 1);
        assert_eq!(packet_id(&start[0]), PacketId::CoreServerAnnounce);
        // Minor version 12, like a Windows server.
        assert_eq!(bytes(&start[0])[6..8], VERSION_MINOR_12.to_le_bytes());

        let reply = server
            .process(&from_client(RdpdrPdu::VersionAndIdPdu(VersionAndIdPdu {
                version_major: 1,
                version_minor: 12,
                client_id: 0x77,
                kind: VersionAndIdPduKind::ClientAnnounceReply,
            })))
            .unwrap();
        let ids: Vec<_> = reply.iter().map(packet_id).collect();
        assert_eq!(ids, [PacketId::CoreServerCapability, PacketId::CoreClientidConfirm]);
        assert_eq!(bytes(&reply[1])[8..12], 0x77u32.to_le_bytes());

        let name = ClientNameRequest::new("DESKTOP-01".to_owned(), ClientNameRequestUnicodeFlag::Unicode);
        assert!(server.process(&from_client(RdpdrPdu::ClientNameRequest(name))).unwrap().is_empty());
        assert_eq!(recorder.0.lock().unwrap().client_name.as_deref(), Some("DESKTOP-01"));

        let capabilities = CoreCapability {
            capabilities: Capabilities::new().clone_inner(),
            kind: CoreCapabilityKind::ClientCoreCapabilityResponse,
        };
        let logged_on = server.process(&from_client(RdpdrPdu::CoreCapability(capabilities))).unwrap();
        assert_eq!(logged_on.iter().map(packet_id).collect::<Vec<_>>(), [PacketId::CoreUserLoggedon]);
        assert!(recorder.0.lock().unwrap().handle.is_some());
    }

    #[test]
    fn drives_are_accepted_and_other_devices_declined() {
        let (mut server, recorder, _receiver) = server();
        let replies = server
            .process(&announce(&[
                (0x08, 1, b"C\0\0\0\0\0\0\0", &utf16z("C on DESKTOP")),
                (0x08, 2, b"Document", b"Documents_2026\0"),
                (0x08, 3, b"ignored\0", b"Photos\0"),
                (0x08, 4, b"D:\0\0\0\0\0\0", b""),
                (0x04, 5, b"PRN1\0\0\0\0", b""),
            ]))
            .unwrap();
        let results: Vec<(u32, u32)> = replies
            .iter()
            .map(|message| {
                let bytes = bytes(message);
                (
                    u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                    u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                )
            })
            .collect();
        let not_supported = u32::from(NtStatus::NOT_SUPPORTED);
        assert_eq!(results, [(1, 0), (2, 0), (3, 0), (4, 0), (5, not_supported)]);

        let names: Vec<_> = recorder
            .0
            .lock()
            .unwrap()
            .announced
            .iter()
            .map(|d| (d.device_id, d.name.clone()))
            .collect();
        assert_eq!(
            names,
            [
                (1, "C on DESKTOP".to_owned()),
                (2, "Documents_2026".to_owned()),
                (3, "Photos".to_owned()),
                (4, "D".to_owned()),
            ]
        );
    }

    #[test]
    fn device_removal_reaches_the_backend() {
        let (mut server, recorder, _receiver) = server();
        let remove = ClientDeviceListRemove { device_list: vec![2, 3] };
        assert!(server
            .process(&from_client(RdpdrPdu::ClientDeviceListRemove(remove)))
            .unwrap()
            .is_empty());
        assert_eq!(recorder.0.lock().unwrap().removed, [2, 3]);
    }

    #[test]
    fn drive_names_are_read_in_either_encoding() {
        assert_eq!(drive_name(&utf16z("C on DESKTOP")).as_deref(), Some("C on DESKTOP"));
        assert_eq!(drive_name(b"home\0").as_deref(), Some("home"));
        assert_eq!(drive_name(b"abc\0").as_deref(), Some("abc"));
        // "文档" (documents), in both encodings.
        assert_eq!(drive_name(&utf16z("\u{6587}\u{6863}")).as_deref(), Some("\u{6587}\u{6863}"));
        assert_eq!(drive_name("\u{6587}\u{6863}\0".as_bytes()).as_deref(), Some("\u{6587}\u{6863}"));
        assert_eq!(drive_name(b"\0"), None);
        assert_eq!(drive_name(b""), None);
    }

    #[tokio::test]
    async fn stat_opens_queries_and_closes() {
        let (mut server, recorder, mut receiver) = server();
        let handle = recorder.0.lock().unwrap().handle.clone().unwrap();
        let task = tokio::spawn(async move { handle.stat(1, "\\docs\\a.txt").await });

        let answer = |server: &mut RdpdrServer, pdu: RdpdrPdu| {
            assert!(server.process(&from_client(pdu)).unwrap().is_empty());
        };

        tokio::task::yield_now().await;
        let open = next_request(&mut receiver);
        let ServerDriveIoRequest::ServerCreateDriveRequest(create) = &open else {
            panic!("expected a create, got {open:?}");
        };
        assert_eq!(create.path, "\\docs\\a.txt");
        assert_eq!(create.create_disposition, CreateDisposition::FILE_OPEN);
        answer(
            &mut server,
            RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: response(completion_id(&open), NtStatus::SUCCESS),
                file_id: 5,
                information: Information::FILE_OPENED,
            }),
        );

        tokio::task::yield_now().await;
        let basic = next_request(&mut receiver);
        answer(
            &mut server,
            RdpdrPdu::ClientDriveQueryInformationResponse(ClientDriveQueryInformationResponse {
                device_io_response: response(completion_id(&basic), NtStatus::SUCCESS),
                buffer: Some(FileInformationClass::Basic(FileBasicInformation {
                    creation_time: 1,
                    last_access_time: 2,
                    last_write_time: 3,
                    change_time: 4,
                    file_attributes: FileAttributes::FILE_ATTRIBUTE_ARCHIVE,
                })),
            }),
        );

        tokio::task::yield_now().await;
        let standard = next_request(&mut receiver);
        answer(
            &mut server,
            RdpdrPdu::ClientDriveQueryInformationResponse(ClientDriveQueryInformationResponse {
                device_io_response: response(completion_id(&standard), NtStatus::SUCCESS),
                buffer: Some(FileInformationClass::Standard(FileStandardInformation {
                    allocation_size: 4096,
                    end_of_file: 1234,
                    number_of_links: 1,
                    delete_pending: Boolean::False,
                    directory: Boolean::False,
                })),
            }),
        );

        tokio::task::yield_now().await;
        let close = next_request(&mut receiver);
        assert!(matches!(close, ServerDriveIoRequest::DeviceCloseRequest(ref c) if c.device_io_request.file_id == 5));
        answer(
            &mut server,
            RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                device_io_response: response(completion_id(&close), NtStatus::SUCCESS),
            }),
        );

        let info = task.await.unwrap().unwrap();
        assert_eq!(
            info,
            FileInfo {
                size: 1234,
                attributes: FileAttributes::FILE_ATTRIBUTE_ARCHIVE,
                creation_time: 1,
                last_access_time: 2,
                last_write_time: 3,
                change_time: 4,
            }
        );
    }

    #[tokio::test]
    async fn listing_stops_at_no_more_files() {
        let (mut server, recorder, mut receiver) = server();
        let handle = recorder.0.lock().unwrap().handle.clone().unwrap();
        let task = tokio::spawn(async move { handle.list_dir(1, "\\").await });

        tokio::task::yield_now().await;
        let open = next_request(&mut receiver);
        server
            .process(&from_client(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: response(completion_id(&open), NtStatus::SUCCESS),
                file_id: 8,
                information: Information::FILE_OPENED,
            })))
            .unwrap();

        let entries = [".", "..", "a.txt", "sub"];
        for (i, name) in entries.iter().enumerate() {
            tokio::task::yield_now().await;
            let query = next_request(&mut receiver);
            let ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(q) = &query else {
                panic!("expected a directory query, got {query:?}");
            };
            // Only the first query carries the pattern.
            assert_eq!(q.path, if i == 0 { "\\*" } else { "" });
            let attributes = if *name == "sub" {
                FileAttributes::FILE_ATTRIBUTE_DIRECTORY
            } else {
                FileAttributes::FILE_ATTRIBUTE_ARCHIVE
            };
            server
                .process(&from_client(RdpdrPdu::ClientDriveQueryDirectoryResponse(
                    ClientDriveQueryDirectoryResponse {
                        device_io_reply: response(completion_id(&query), NtStatus::SUCCESS),
                        buffer: Some(FileInformationClass::Directory(FileDirectoryInformation::new(
                            0,
                            0,
                            7,
                            0,
                            42,
                            attributes,
                            (*name).to_owned(),
                        ))),
                    },
                )))
                .unwrap();
        }
        tokio::task::yield_now().await;
        let last = next_request(&mut receiver);
        server
            .process(&from_client(RdpdrPdu::ClientDriveQueryDirectoryResponse(
                ClientDriveQueryDirectoryResponse {
                    device_io_reply: response(completion_id(&last), NtStatus::NO_MORE_FILES),
                    buffer: None,
                },
            )))
            .unwrap();
        tokio::task::yield_now().await;
        let close = next_request(&mut receiver);
        server
            .process(&from_client(RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                device_io_response: response(completion_id(&close), NtStatus::SUCCESS),
            })))
            .unwrap();

        let listed = task.await.unwrap().unwrap();
        let names: Vec<_> = listed.iter().map(|e| (e.name.as_str(), e.info.is_dir())).collect();
        assert_eq!(names, [("a.txt", false), ("sub", true)]);
        assert_eq!(listed[0].info.size, 42);
        assert_eq!(listed[0].info.last_write_time, 7);
    }

    /// Answers every request of a task with success, recording the requests, until the task ends.
    async fn answer_all<T>(
        server: &mut RdpdrServer,
        receiver: &mut mpsc::UnboundedReceiver<ServerEvent>,
        mut task: tokio::task::JoinHandle<T>,
    ) -> (T, Vec<ServerDriveIoRequest>) {
        let mut requests = Vec::new();
        loop {
            tokio::task::yield_now().await;
            if task.is_finished() {
                return ((&mut task).await.unwrap(), requests);
            }
            let Ok(ServerEvent::Rdpdr(RdpdrServerMessage::SendMessages(messages))) = receiver.try_recv() else {
                continue;
            };
            let bytes = bytes(&messages[0]);
            let mut src = ReadCursor::new(&bytes);
            SharedHeader::decode(&mut src).unwrap();
            let io = DeviceIoRequest::decode(&mut src).unwrap();
            let request = ServerDriveIoRequest::decode(io, &mut src).unwrap();
            let id = completion_id(&request);
            let reply = match &request {
                ServerDriveIoRequest::ServerCreateDriveRequest(_) => RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                    device_io_reply: response(id, NtStatus::SUCCESS),
                    file_id: 9,
                    information: Information::FILE_OPENED,
                }),
                ServerDriveIoRequest::DeviceCloseRequest(_) => RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                    device_io_response: response(id, NtStatus::SUCCESS),
                }),
                ServerDriveIoRequest::ServerDriveSetInformationRequest(set) => {
                    RdpdrPdu::ClientDriveSetInformationResponse(
                        ironrdp_rdpdr::pdu::efs::ClientDriveSetInformationResponse::new(set, NtStatus::SUCCESS).unwrap(),
                    )
                }
                other => panic!("no answer for {other:?}"),
            };
            requests.push(request);
            server.process(&from_client(reply)).unwrap();
        }
    }

    #[tokio::test]
    async fn create_modes_and_times_reach_the_client() {
        let (mut server, recorder, mut receiver) = server();
        let handle = recorder.0.lock().unwrap().handle.clone().unwrap();

        for (mode, disposition) in [
            (CreateMode::Exclusive, CreateDisposition::FILE_CREATE),
            (CreateMode::Open, CreateDisposition::FILE_OPEN_IF),
            (CreateMode::Truncate, CreateDisposition::FILE_OVERWRITE_IF),
        ] {
            let task = tokio::spawn({
                let handle = handle.clone();
                async move { handle.create_file(1, "\\new.txt", mode).await }
            });
            let (result, requests) = answer_all(&mut server, &mut receiver, task).await;
            result.unwrap();
            let ServerDriveIoRequest::ServerCreateDriveRequest(create) = &requests[0] else {
                panic!("expected a create, got {:?}", requests[0]);
            };
            assert_eq!(create.create_disposition, disposition, "{mode:?}");
        }

        let task = tokio::spawn({
            let handle = handle.clone();
            async move { handle.set_times(1, "\\new.txt", None, Some(133_000_000_000_000_000)).await }
        });
        let (result, requests) = answer_all(&mut server, &mut receiver, task).await;
        result.unwrap();
        let ServerDriveIoRequest::ServerDriveSetInformationRequest(set) = &requests[1] else {
            panic!("expected a set information, got {:?}", requests[1]);
        };
        assert_eq!(
            set.set_buffer,
            FileInformationClass::Basic(FileBasicInformation {
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 133_000_000_000_000_000,
                change_time: 0,
                file_attributes: FileAttributes::empty(),
            })
        );
    }

    #[tokio::test]
    async fn a_failure_status_is_reported() {
        let (mut server, recorder, mut receiver) = server();
        let handle = recorder.0.lock().unwrap().handle.clone().unwrap();
        let task = tokio::spawn(async move { handle.stat(1, "\\missing").await });

        tokio::task::yield_now().await;
        let open = next_request(&mut receiver);
        server
            .process(&from_client(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: response(completion_id(&open), NtStatus::OBJECT_NAME_NOT_FOUND),
                file_id: 0,
                information: Information::empty(),
            })))
            .unwrap();
        assert_eq!(
            task.await.unwrap(),
            Err(RdpdrError::Status {
                op: "create",
                status: NtStatus::OBJECT_NAME_NOT_FOUND
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_without_an_answer_times_out() {
        let (_server, recorder, mut receiver) = server();
        let handle = recorder
            .0
            .lock()
            .unwrap()
            .handle
            .clone()
            .unwrap()
            .with_timeout(Duration::from_secs(5));
        let result = handle.stat(1, "\\slow").await;
        assert_eq!(result, Err(RdpdrError::Timeout { op: "create" }));
        assert!(matches!(
            next_request(&mut receiver),
            ServerDriveIoRequest::ServerCreateDriveRequest(_)
        ));
    }

    #[tokio::test]
    async fn waiting_requests_fail_when_the_connection_ends() {
        let (server, recorder, _receiver) = server();
        let handle = recorder.0.lock().unwrap().handle.clone().unwrap();
        let task = tokio::spawn({
            let handle = handle.clone();
            async move { handle.stat(1, "\\a").await }
        });
        tokio::task::yield_now().await;
        drop(server);
        assert_eq!(task.await.unwrap(), Err(RdpdrError::Closed));
        // And later requests fail at once.
        assert_eq!(handle.stat(1, "\\b").await, Err(RdpdrError::Closed));
    }
}
