use libfuse_sys as ffi;

use ffi::fuse;
use libc::{c_int, flock};
use nix::{
    errno::Errno::ENOSYS,
    fcntl::{FcntlArg, OFlag},
    sys::{stat::Mode, statvfs::Statvfs, time::TimeSpec},
    unistd::{AccessFlags, Gid, Uid},
};
use std::{
    ffi::{OsStr, OsString},
    mem,
    ops::{Deref, DerefMut},
    path::Path,
};

use super::Result;

libc_bitflags! {
    // TODO: should be plural?
    pub struct XAttrOption: libc::c_int {
        XATTR_CREATE;
        XATTR_REPLACE;
        #[cfg(target_os = "macos")]
        XATTR_NOFOLLOW;
        #[cfg(target_os = "macos")]
        XATTR_NODEFAULT;
        #[cfg(target_os = "macos")]
        XATTR_NOSECURITY;
        #[cfg(target_os = "macos")]
        XATTR_SHOWCOMPRESSION;
    }
}

bitflags! {
    struct BufferFlag: fuse::fuse_buf_flags {
        const FUSE_BUF_IS_FD    = fuse::fuse_buf_flags_FUSE_BUF_IS_FD;
        const FUSE_BUF_FD_SEEK  = fuse::fuse_buf_flags_FUSE_BUF_FD_SEEK;
        const FUSE_BUF_FD_RETRY = fuse::fuse_buf_flags_FUSE_BUF_FD_RETRY;
    }
}

bitflags! {
    pub struct CapabilityFlags: u32 {
        // Filesystem supports asynchronous read requests.
        const FUSE_CAP_ASYNC_READ = fuse::FUSE_CAP_ASYNC_READ;

        // Filesystem supports "remote" locking.
        const FUSE_CAP_POSIX_LOCKS = fuse::FUSE_CAP_POSIX_LOCKS;

        // Filesystem handles the O_TRUNC open flag.
        const FUSE_CAP_ATOMIC_O_TRUNC = fuse::FUSE_CAP_ATOMIC_O_TRUNC;

        // Filesystem handles lookups of "." and "..".
        const FUSE_CAP_EXPORT_SUPPORT = fuse::FUSE_CAP_EXPORT_SUPPORT;

        // Filesystem can handle write size larger than 4kB.
        const FUSE_CAP_BIG_WRITES = fuse::FUSE_CAP_BIG_WRITES;

        // Don't apply umask to file mode on create operations.
        const FUSE_CAP_DONT_MASK = fuse::FUSE_CAP_DONT_MASK;

        // Ability to use splice() to write to the fuse device.
        const FUSE_CAP_SPLICE_WRITE = fuse::FUSE_CAP_SPLICE_WRITE;

        // Ability to move data to the fuse device with splice().
        const FUSE_CAP_SPLICE_MOVE = fuse::FUSE_CAP_SPLICE_MOVE;

        // Ability to use splice() to read from the fuse device.
        const FUSE_CAP_SPLICE_READ = fuse::FUSE_CAP_SPLICE_READ;

        // Ioctl support on directories.
        const FUSE_CAP_IOCTL_DIR = fuse::FUSE_CAP_IOCTL_DIR;

        #[cfg(target_os = "macos")]
        const FUSE_CAP_ALLOCATE         = fuse::FUSE_CAP_ALLOCATE;
        #[cfg(target_os = "macos")]
        const FUSE_CAP_EXCHANGE_DATA    = fuse::FUSE_CAP_EXCHANGE_DATA;
        #[cfg(target_os = "macos")]
        const FUSE_CAP_CASE_INSENSITIVE = fuse::FUSE_CAP_CASE_INSENSITIVE;
        #[cfg(target_os = "macos")]
        const FUSE_CAP_VOL_RENAME       = fuse::FUSE_CAP_VOL_RENAME;
        #[cfg(target_os = "macos")]
        const FUSE_CAP_XTIMES           = fuse::FUSE_CAP_XTIMES;
    }
}

#[derive(Debug)]
pub struct FileStat(libc::stat);

impl FileStat {
    pub fn new() -> Self {
        unsafe { mem::zeroed() }
    }

    pub(crate) fn fill(&self, cstat: *mut libc::stat) -> c_int {
        assert!(!cstat.is_null());
        unsafe {
            (*cstat).st_dev = self.st_dev;
            (*cstat).st_mode = self.st_mode;
            (*cstat).st_nlink = self.st_nlink;
            (*cstat).st_ino = self.st_ino;
            (*cstat).st_uid = self.st_uid;
            (*cstat).st_gid = self.st_gid;
            (*cstat).st_rdev = self.st_rdev;
            (*cstat).st_atime = self.st_atime;
            (*cstat).st_atime_nsec = self.st_atime_nsec;
            (*cstat).st_mtime = self.st_mtime;
            (*cstat).st_mtime_nsec = self.st_mtime_nsec;
            (*cstat).st_ctime = self.st_ctime;
            (*cstat).st_ctime_nsec = self.st_ctime_nsec;
            (*cstat).st_size = self.st_size;
            (*cstat).st_blocks = self.st_blocks;
            (*cstat).st_blksize = self.st_blksize;
            cfg_if::cfg_if! {
                if #[cfg(target_os = "macos")]  {
                    (*cstat).st_birthtime = self.st_birthtime;
                    (*cstat).st_birthtime_nsec = self.st_birthtime_nsec;
                    (*cstat).st_flags = self.st_flags;
                    (*cstat).st_gen = self.st_gen;
                    (*cstat).st_lspare = self.st_lspare;
                    (*cstat).st_qspare = self.st_qspare;
                }
            }
        }
        0
    }

    pub(crate) fn as_raw(&mut self) -> *mut libc::stat {
        &mut self.0
    }
}

impl Default for FileStat {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for FileStat {
    type Target = libc::stat;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FileStat {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct DirEntry {
    pub name: OsString,
    pub metadata: Option<FileStat>,
    pub offset: Option<u64>,
}

#[derive(Debug)]
pub struct ConnectionInfo {
    // Major version of the protocol.
    proto_major: u32,
    // Minor version of the protocol.
    proto_minor: u32,
    // Is async read supported.
    async_read: bool,
    // Maximum size of the write buffer. If set to less than 4096 it is
    // increased to that value.
    max_write: u32,
    // Maximum read ahead size.
    max_readahead: u32,
    // The capabilities supported by the FUSE kernel module.
    kernel_capability_flags: CapabilityFlags,
    // The capabilities desired by the filesystem.
    fs_capability_flags: CapabilityFlags,
    // Maximum number of background requests.
    max_background: u32,
    // Kernel congestion threshold.
    congestion_threshold: u32,
}

impl ConnectionInfo {
    pub(crate) fn from_raw(c: *mut fuse::fuse_conn_info) -> Self {
        unsafe {
            Self {
                proto_minor: (*c).proto_minor,
                proto_major: (*c).proto_major,
                async_read: (*c).async_read == 1,
                max_write: (*c).max_write,
                max_readahead: (*c).max_readahead,
                max_background: (*c).max_background,
                kernel_capability_flags: CapabilityFlags::from_bits_unchecked((*c).capable),
                fs_capability_flags: CapabilityFlags::from_bits_unchecked((*c).want),
                congestion_threshold: (*c).congestion_threshold,
            }
        }
    }
    pub fn proto_major(&self) -> u32 {
        self.proto_major
    }

    pub fn proto_minor(&self) -> u32 {
        self.proto_minor
    }

    pub fn support_async_read(&mut self) -> &mut Self {
        self.async_read = true;
        self
    }

    pub fn set_max_write_buffer(&mut self, size: u32) -> &mut Self {
        self.max_write = size;
        self
    }

    pub fn set_max_readahead(&mut self, size: u32) -> &mut Self {
        self.max_readahead = size;
        self
    }

    pub fn set_max_background_requests(&mut self, max: u32) -> &mut Self {
        self.max_background = max;
        self
    }

    pub fn set_congestion_threshold(&mut self, threshold: u32) -> &mut Self {
        self.congestion_threshold = threshold;
        self
    }

    pub fn kernel_capability_flags(&self) -> CapabilityFlags {
        self.kernel_capability_flags
    }

    pub fn set_capability_flags(&mut self, flags: CapabilityFlags) -> &mut Self {
        self.fs_capability_flags = flags;
        self
    }
}

#[derive(Default, Debug)]
pub struct FileInfo {
    // Open flags. Available in `open` and `release`.
    flags: Option<OFlag>,

    // In case of a write operation indicates if this was caused by a delayed
    // write from the page cache.
    writepage: bool,

    // Can be filled in by open, to use direct I/O on this file.
    direct_io: bool,

    // Can be filled in by open. It signals the kernel that any currently cached
    // file data (ie., data that the filesystem provided the last time the file
    // was open) need not be invalidated. Has no effect when set in other
    // contexts (in particular it does nothing when set by opendir()).
    keep_cache: bool,

    // Indicates a flush operation.
    flush: bool,

    // Indicates whether the file is seekable or not.
    non_seekable: bool,

    // Indicates that flock locks for the file should be released.
    release_flock: bool,

    // File handle id. May be filled in `create`, `open`, and `opendir`.
    // Available in most other file operations on the same file handle.
    handle: Option<u64>,

    // Lock owner id. Available in locking operations and flush.
    lock_owner_id: Option<u64>,
}

impl FileInfo {
    pub fn handle(&self) -> Option<u64> {
        self.handle
    }

    pub(crate) fn from_raw(fi: *mut fuse::fuse_file_info) -> Self {
        assert!(!fi.is_null());
        unsafe {
            Self {
                flags: OFlag::from_bits((*fi).flags),
                writepage: (*fi).writepage == 1,
                handle: Some((*fi).fh),
                lock_owner_id: Some((*fi).lock_owner),
                direct_io: (*fi).direct_io() == 1,
                keep_cache: (*fi).keep_cache() == 1,
                flush: (*fi).flush() == 1,
                non_seekable: (*fi).nonseekable() == 1,
                release_flock: (*fi).flock_release() == 1,
            }
        }
    }

    pub(crate) fn fill(&self, fi: *mut fuse::fuse_file_info) -> libc::c_int {
        assert!(!fi.is_null());
        unsafe {
            (*fi).flags = self.flags.map_or((*fi).flags, |o| o.bits());
            (*fi).writepage = self.writepage as libc::c_int;
            (*fi).fh = self.handle.unwrap_or((*fi).fh);
            (*fi).lock_owner = self.lock_owner_id.unwrap_or((*fi).lock_owner);
            (*fi).set_direct_io(self.direct_io as libc::c_uint);
            (*fi).set_keep_cache(self.keep_cache as libc::c_uint);
            (*fi).set_flush(self.flush as libc::c_uint);
            (*fi).set_nonseekable(self.non_seekable as libc::c_uint);
            (*fi).set_flock_release(self.release_flock as libc::c_uint);
        }
        0
    }
}

#[derive(Default, Debug)]
pub struct OpenFileInfo(FileInfo);

impl OpenFileInfo {
    pub(crate) fn from_file_info(fi: FileInfo) -> Self {
        Self(fi)
    }

    pub(crate) fn file_info(&self) -> &FileInfo {
        &self.0
    }

    pub fn flags(&self) -> Option<OFlag> {
        self.0.flags
    }

    pub fn set_handle(&mut self, handle: u64) -> &mut Self {
        self.0.handle = Some(handle);
        self
    }

    pub fn set_direct_io(&mut self, direct_io: bool) -> &mut Self {
        self.0.direct_io = direct_io;
        self
    }

    pub fn set_keep_cache(&mut self, keep_cache: bool) -> &mut Self {
        self.0.keep_cache = keep_cache;
        self
    }

    pub fn set_non_seekable(&mut self, non_seekable: bool) -> &mut Self {
        self.0.non_seekable = non_seekable;
        self
    }
}

#[derive(Debug)]
pub struct WriteFileInfo(FileInfo);

impl WriteFileInfo {
    pub(crate) fn from_file_info(fi: FileInfo) -> Self {
        Self(fi)
    }

    pub(crate) fn file_info(&self) -> &FileInfo {
        &self.0
    }

    pub fn set_writepage(&mut self, writepage: bool) -> &mut Self {
        self.0.writepage = writepage;
        self
    }

    pub fn handle(&self) -> Option<u64> {
        self.0.handle()
    }
}

#[derive(Debug)]
pub struct FlushFileInfo(FileInfo);

impl FlushFileInfo {
    pub(crate) fn from_file_info(fi: FileInfo) -> Self {
        Self(fi)
    }

    pub(crate) fn file_info(&self) -> &FileInfo {
        &self.0
    }

    pub fn handle(&self) -> Option<u64> {
        self.0.handle()
    }

    pub fn set_flush(&mut self, flush: bool) -> &mut Self {
        self.0.flush = flush;
        self
    }

    pub fn lock_owner_id(&self) -> Option<u64> {
        self.0.lock_owner_id
    }
}

#[derive(Debug)]
pub struct LockFileInfo(FileInfo);

impl LockFileInfo {
    pub fn handle(&self) -> Option<u64> {
        self.0.handle()
    }

    pub fn set_lock_owner_id(&mut self, id: u64) -> &mut Self {
        self.0.lock_owner_id = Some(id);
        self
    }

    pub fn lock_owner_id(&self) -> Option<u64> {
        self.0.lock_owner_id
    }
}

#[derive(Debug)]
pub struct ReleaseFileInfo(FileInfo);

impl ReleaseFileInfo {
    pub(crate) fn from_file_info(fi: FileInfo) -> Self {
        Self(fi)
    }

    pub(crate) fn file_info(&self) -> &FileInfo {
        &self.0
    }

    pub fn handle(&self) -> Option<u64> {
        self.0.handle()
    }

    pub fn flags(&self) -> Option<OFlag> {
        self.0.flags
    }

    pub fn set_release_flock(&mut self, release_flock: bool) -> &mut Self {
        self.0.release_flock = release_flock;
        self
    }
}

pub trait Filesystem {
    // Get file attributes of given path.
    fn metadata(&self, _path: &Path) -> Result<FileStat> {
        Err(ENOSYS)
    }

    // Read the target of a symbolic link.
    fn read_link(&self, _path: &Path) -> Result<&OsStr> {
        Err(ENOSYS)
    }

    // Create a directory.
    fn create_dir(&mut self, _path: &Path, _mode: Mode) -> Result<()> {
        Err(ENOSYS)
    }

    // Remove a file.
    fn remove_file(&mut self, _path: &Path) -> Result<()> {
        Err(ENOSYS)
    }

    // Remove a directory.
    fn remove_dir(&mut self, _path: &Path) -> Result<()> {
        Err(ENOSYS)
    }

    // Create a symbolic link.
    fn symlink(&mut self, _src: &Path, _dst: &Path) -> Result<()> {
        Err(ENOSYS)
    }

    // Rename a file
    fn rename(&mut self, _from: &Path, _to: &Path) -> Result<()> {
        Err(ENOSYS)
    }

    // Create a hard link.
    fn hard_link(&mut self, _src: &Path, _dst: &Path) -> Result<()> {
        Err(ENOSYS)
    }

    // Change the permissions found on a file.
    fn set_permissions(&mut self, _path: &Path, _mode: Mode) -> Result<()> {
        Err(ENOSYS)
    }

    // Change the ownership of a file.
    fn set_owner(&mut self, _path: &Path, _uid: Uid, _gid: Gid) -> Result<()> {
        Err(ENOSYS)
    }

    // Truncate or extend the size of a file.
    // TODO: rename to truncate?
    fn set_len(&mut self, _path: &Path, _len: u64) -> Result<()> {
        Err(ENOSYS)
    }

    // Open a file.
    fn open(&mut self, _path: &Path, _file_info: &mut OpenFileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Read data from file.
    fn read(
        &mut self,
        _path: &Path,
        _buf: &mut [u8],
        _offset: u64,
        _file_info: FileInfo,
    ) -> Result<usize> {
        Err(ENOSYS)
    }

    // Write data to a file.
    fn write(
        &mut self,
        _path: &Path,
        _buf: &[u8],
        _offset: u64,
        _file_info: &mut WriteFileInfo,
    ) -> Result<usize> {
        Err(ENOSYS)
    }

    // Get filesystem statistics.
    fn statfs(&self, _path: &Path) -> Result<Statvfs> {
        Err(ENOSYS)
    }

    // Possibly flush cached data.
    fn flush(&mut self, _path: &Path, _file_info: &mut FlushFileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Release an open file.
    fn release(&mut self, _path: &Path, _file_info: &mut ReleaseFileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Synchronise file contents but not metadata.
    fn sync_data(&mut self, _path: &Path, _file_info: FileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Synchronise file contents and metadata.
    fn sync_all(&mut self, _path: &Path, _file_info: FileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Set extended attribute.
    #[cfg(target_os = "macos")]
    fn set_ext_metadata(
        &mut self,
        _path: &Path,
        _name: String,
        _value: &[u8],
        _options: XAttrOption,
        _position: u32,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    // Set extended attribute.
    #[cfg(target_os = "linux")]
    fn set_ext_metadata(
        &mut self,
        _path: &Path,
        _name: String,
        _value: &[u8],
        _options: XAttrOption,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    // Get extended attribute.
    #[cfg(target_os = "macos")]
    fn get_ext_metadata(
        &self,
        _path: &Path,
        _name: String,
        _buf: &[u8],
        _options: XAttrOption,
        _position: u32,
    ) -> Result<usize> {
        Err(ENOSYS)
    }

    // Get extended attribute.
    #[cfg(target_os = "linux")]
    fn get_ext_metadata(
        &self,
        _path: &Path,
        _name: String,
        _buf: &[u8],
        _options: XAttrOption,
    ) -> Result<usize> {
        Err(ENOSYS)
    }

    // List extended attributes.
    // TODO: change to iterator
    fn list_ext_metadata(&self, _path: &Path) -> Result<Vec<String>> {
        Err(ENOSYS)
    }

    // Remove extended attribute.
    fn remove_ext_metadata(&mut self, _path: &Path, _name: String) -> Result<()> {
        Err(ENOSYS)
    }

    // Open directory.
    fn open_dir(&mut self, _path: &Path, _file_info: &mut OpenFileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Read directory.
    // TODO: change to iterator
    fn read_dir(
        &mut self,
        _path: &Path,
        _offset: u64,
        _file_info: FileInfo,
    ) -> Result<Vec<DirEntry>> {
        Err(ENOSYS)
    }

    // Release directory.
    fn release_dir(&mut self, _path: &Path, _file_info: ReleaseFileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Synchronise directory contents but not metadata.
    fn sync_dir_data(&mut self, _path: &Path, _file_info: FileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Synchronise directory contents and metadata.
    fn sync_dir_all(&mut self, _path: &Path, _file_info: FileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Initialise filesystem.
    fn init(&mut self, _connection_info: &mut ConnectionInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Clean up filesystem.
    fn destroy(&mut self) -> Result<()> {
        Err(ENOSYS)
    }

    // Check permissions for a file.
    fn check_permissions(&self, _path: &Path, _permissions: AccessFlags) -> Result<bool> {
        Err(ENOSYS)
    }

    // Create and open a file.
    fn create(
        &mut self,
        _path: &Path,
        _permissions: Mode,
        _file_info: &mut OpenFileInfo,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    // Change the size of an open file.
    fn ftruncate(&mut self, _path: &Path, _len: u64, _file_info: FileInfo) -> Result<()> {
        Err(ENOSYS)
    }

    // Get attributes from an open file.
    fn fmetadata(&self, _path: &Path, _file_info: FileInfo) -> Result<FileStat> {
        Err(ENOSYS)
    }

    // Perform POSIX locking operation.
    fn lock(
        &mut self,
        _path: &Path,
        _file_info: LockFileInfo,
        _command: FcntlArg,
        _file_lock: flock,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    // Change the access and modification time of a file with nanosecond resolution.
    fn utimens(&mut self, _path: &Path, _atime: TimeSpec, _mtime: TimeSpec) -> Result<()> {
        Err(ENOSYS)
    }

    // Map block index within file to block index within device.
    fn bmap(&self, _path: &Path, _blocksize: usize, _index: u64) -> Result<u64> {
        Err(ENOSYS)
    }

    // TODO: ioctl, poll, write_buf, read_buf, flock, fallocate, macos specific functions.
}
