extern crate once_cell;

use libfuse_sys as ffi;

use crate::filesystem::{
    ConnectionInfo, FileInfo, Filesystem, FlushFileInfo, OpenFileInfo, ReleaseFileInfo,
    WriteFileInfo,
};
use ffi::fuse;
use libc::{c_char, c_int, gid_t, mode_t, off_t, stat, uid_t};
use nix::{
    errno::Errno::{self, EINVAL},
    sys::{stat::Mode, statvfs::Statvfs},
    unistd::{AccessFlags, Gid, Uid},
};
use once_cell::sync::OnceCell;
use std::{
    ffi::{c_void, CStr, CString, OsString},
    ops::{Deref, DerefMut},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
    sync::{RwLock, RwLockReadGuard},
};

static mut FS: OnceCell<RwLock<FilesystemImpl>> = OnceCell::new();

#[derive(Debug)]
pub enum Error {
    AlreadyMountedError,
    MountError,
}

pub fn mount<P, I>(
    name: OsString,
    mountpoint: P,
    filesystem: &'static mut dyn Filesystem,
    args: I,
) -> Result<(), Error>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = OsString>,
{
    unsafe {
        setup_fs(filesystem)?;

        let mut argv = vec![
            CString::from_vec_unchecked(name.into_vec()).into_raw(),
            CString::from_vec_unchecked(mountpoint.as_ref().as_os_str().to_os_string().into_vec())
                .into_raw(),
        ];

        argv.append(
            &mut args
                .into_iter()
                .map(|a| CString::from_vec_unchecked(a.into_vec()).into_raw())
                .collect::<Vec<*mut c_char>>(),
        );

        match fuse::fuse_main(
            argv.len() as c_int,
            argv.as_mut_ptr(),
            &build_operations(),
            std::ptr::null_mut(),
        ) {
            0 => Ok(()),
            _ => Err(Error::MountError),
        }
    }
}

unsafe extern "C" fn getattr(p: *const c_char, stat: *mut stat) -> c_int {
    if stat.is_null() {
        return negate_errno(EINVAL);
    }

    match build_path(p) {
        Ok(path) => match get_fs().metadata(path) {
            Ok(file_stat) => file_stat.fill(stat),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn readlink(p: *const c_char, buffer: *mut c_char, len: usize) -> c_int {
    if buffer.is_null() {
        return negate_errno(EINVAL);
    }

    match build_path(p) {
        Ok(path) => match get_fs().read_link(path) {
            Ok(path) => {
                let cstr = CString::new(&path.as_bytes()[..len - 1]).unwrap();
                std::ptr::copy_nonoverlapping(
                    cstr.into_bytes_with_nul().as_ptr() as *const _,
                    buffer,
                    len,
                );
                0
            }
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn mkdir(p: *const c_char, mode: mode_t) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().create_dir(path, Mode::from_bits_unchecked(mode))),
        Err(err) => err,
    }
}

unsafe extern "C" fn unlink(p: *const c_char) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().remove_file(path)),
        Err(err) => err,
    }
}

unsafe extern "C" fn rmdir(p: *const c_char) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().remove_dir(path)),
        Err(err) => err,
    }
}

unsafe extern "C" fn symlink(src: *const c_char, dst: *const c_char) -> c_int {
    match build_path(src) {
        Ok(src) => match build_path(dst) {
            Ok(dst) => unit_op!(get_mut_fs().symlink(src, dst)),
            Err(err) => err,
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn rename(from: *const c_char, to: *const c_char) -> c_int {
    match build_path(from) {
        Ok(from) => match build_path(to) {
            Ok(to) => unit_op!(get_mut_fs().rename(from, to)),
            Err(err) => err,
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn link(src: *const c_char, dst: *const c_char) -> c_int {
    match build_path(src) {
        Ok(src) => match build_path(dst) {
            Ok(dst) => unit_op!(get_mut_fs().hard_link(src, dst)),
            Err(err) => err,
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn chmod(p: *const c_char, mode: mode_t) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().set_permissions(path, Mode::from_bits_unchecked(mode))),
        Err(err) => err,
    }
}

unsafe extern "C" fn chown(p: *const c_char, uid: uid_t, gid: gid_t) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().set_owner(path, Uid::from_raw(uid), Gid::from_raw(gid))),
        Err(err) => err,
    }
}

unsafe extern "C" fn truncate(p: *const c_char, len: off_t) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().set_len(path, len as _)),
        Err(err) => err,
    }
}

unsafe extern "C" fn open(p: *const c_char, fi: *mut fuse::fuse_file_info) -> c_int {
    if fi.is_null() {
        return negate_errno(EINVAL);
    }

    let mut open_fi = OpenFileInfo::default();
    match build_path(p) {
        Ok(path) => match get_mut_fs().open(path, &mut open_fi) {
            Ok(_) => open_fi.file_info().fill(fi),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn read(
    p: *const c_char,
    buffer: *mut c_char,
    len: usize,
    offset: off_t,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    if buffer.is_null() {
        return negate_errno(EINVAL);
    }

    let mut buf = Vec::with_capacity(len);
    match build_path(p) {
        Ok(path) => match get_mut_fs().read(path, &mut buf, offset as _, FileInfo::from_raw(fi)) {
            Ok(length) => {
                let len = len.min(length);
                std::ptr::copy_nonoverlapping(
                    CString::from_vec_unchecked(buf).as_ptr(),
                    buffer,
                    len,
                );
                len as _
            }
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn write(
    p: *const c_char,
    buffer: *const c_char,
    len: usize,
    offset: off_t,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    let buf = CStr::from_ptr(buffer);
    let mut write_fi = WriteFileInfo::from_file_info(FileInfo::from_raw(fi));
    match build_path(p) {
        Ok(path) => {
            match get_mut_fs().write(path, buf.to_bytes(), len, offset as _, &mut write_fi) {
                Ok(_len) => write_fi.file_info().fill(fi),
                Err(err) => negate_errno(err),
            }
        }
        Err(err) => err,
    }
}

unsafe extern "C" fn statfs(p: *const c_char, stbuf: *mut libc::statvfs) -> c_int {
    match build_path(p) {
        Ok(path) => match get_fs().statfs(path) {
            Ok(stats) => fill_statvfs(stats, stbuf),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn flush(p: *const c_char, fi: *mut fuse::fuse_file_info) -> c_int {
    let mut flush_fi = FlushFileInfo::from_file_info(FileInfo::from_raw(fi));
    match build_path(p) {
        Ok(path) => match get_mut_fs().flush(path, &mut flush_fi) {
            Ok(_) => flush_fi.file_info().fill(fi),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn release(p: *const c_char, fi: *mut fuse::fuse_file_info) -> c_int {
    let mut release_fi = ReleaseFileInfo::from_file_info(FileInfo::from_raw(fi));
    match build_path(p) {
        Ok(path) => match unit_op!(get_mut_fs().release(path, &mut release_fi)) {
            0 => {
                release_fi.file_info().fill(fi);
                0
            }
            err => err,
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn fsync(
    p: *const c_char,
    data_sync: c_int,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    match build_path(p) {
        Ok(path) => {
            if data_sync == 1 {
                unit_op!(get_mut_fs().sync_data(path, FileInfo::from_raw(fi)))
            } else {
                unit_op!(get_mut_fs().sync_all(path, FileInfo::from_raw(fi)))
            }
        }
        Err(err) => err,
    }
}

unsafe extern "C" fn opendir(p: *const c_char, fi: *mut fuse::fuse_file_info) -> c_int {
    let mut open_fi = OpenFileInfo::from_file_info(FileInfo::from_raw(fi));
    match build_path(p) {
        Ok(path) => match get_mut_fs().open_dir(path, &mut open_fi) {
            Ok(_) => open_fi.file_info().fill(fi),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn readdir(
    p: *const c_char,
    buf: *mut c_void,
    filler: fuse::fuse_fill_dir_t,
    offset: off_t,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    match build_path(p) {
        Ok(path) => match get_mut_fs().read_dir(path, offset as _, FileInfo::from_raw(fi)) {
            Ok(entries) => match filler {
                Some(f) => {
                    for e in entries {
                        let stat = e.metadata.map_or(std::ptr::null(), |mut s| s.as_raw());
                        let res = f(
                            buf,
                            CString::from_vec_unchecked(e.name.into_vec()).as_ptr(),
                            stat,
                            e.offset.unwrap_or(0) as _,
                        );
                        if res != 0 {
                            return res;
                        }
                    }
                    0
                }
                None => 0,
            },
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn fsyncdir(
    p: *const c_char,
    data_sync: c_int,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    match build_path(p) {
        Ok(path) => {
            if data_sync == 1 {
                unit_op!(get_mut_fs().sync_dir_data(path, FileInfo::from_raw(fi)))
            } else {
                unit_op!(get_mut_fs().sync_dir_all(path, FileInfo::from_raw(fi)))
            }
        }
        Err(err) => err,
    }
}

unsafe extern "C" fn releasedir(p: *const c_char, fi: *mut fuse::fuse_file_info) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().release_dir(
            path,
            ReleaseFileInfo::from_file_info(FileInfo::from_raw(fi))
        )),
        Err(err) => err,
    }
}

unsafe extern "C" fn init(conn: *mut fuse::fuse_conn_info) -> *mut c_void {
    assert!(!conn.is_null());
    unit_op!(get_mut_fs().init(&mut ConnectionInfo::from_raw(conn)));
    std::ptr::null_mut()
}

unsafe extern "C" fn destroy(_private_data: *mut c_void) {
    unit_op!(get_mut_fs().destroy());
}

unsafe extern "C" fn access(p: *const c_char, flags: c_int) -> c_int {
    match build_path(p) {
        Ok(path) => match get_fs().check_permissions(path, AccessFlags::from_bits_unchecked(flags))
        {
            Ok(b) => b as c_int,
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn create(
    p: *const c_char,
    mode: mode_t,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    let mut open_fi = OpenFileInfo::from_file_info(FileInfo::from_raw(fi));
    match build_path(p) {
        Ok(path) => {
            match get_mut_fs().create(path, Mode::from_bits_unchecked(mode), &mut open_fi) {
                Ok(_) => open_fi.file_info().fill(fi),
                Err(err) => negate_errno(err),
            }
        }
        Err(err) => err,
    }
}

unsafe extern "C" fn ftruncate(
    p: *const c_char,
    len: off_t,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    match build_path(p) {
        Ok(path) => unit_op!(get_mut_fs().ftruncate(path, len as _, FileInfo::from_raw(fi))),
        Err(err) => err,
    }
}

unsafe extern "C" fn fgetattr(
    p: *const c_char,
    stat: *mut stat,
    fi: *mut fuse::fuse_file_info,
) -> c_int {
    match build_path(p) {
        Ok(path) => match get_fs().fmetadata(path, FileInfo::from_raw(fi)) {
            Ok(file_stat) => file_stat.fill(stat),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

fn fill_statvfs(stvfs: Statvfs, stbuf: *mut libc::statvfs) -> c_int {
    assert!(!stbuf.is_null());
    unsafe {
        (*stbuf).f_bsize = stvfs.block_size();
        (*stbuf).f_frsize = stvfs.fragment_size();
        (*stbuf).f_blocks = stvfs.blocks();
        (*stbuf).f_bfree = stvfs.blocks_free();
        (*stbuf).f_bavail = stvfs.blocks_available();
        (*stbuf).f_files = stvfs.files();
        (*stbuf).f_ffree = stvfs.files_free();
        (*stbuf).f_favail = stvfs.files_available();
        (*stbuf).f_fsid = stvfs.filesystem_id();
        (*stbuf).f_flag = stvfs.flags().bits();
        (*stbuf).f_namemax = stvfs.name_max();
    }
    0
}

unsafe fn build_path<'a>(p: *const c_char) -> Result<&'a Path, c_int> {
    if p.is_null() {
        return Err(negate_errno(EINVAL));
    }

    CStr::from_ptr(p)
        .to_str()
        .map(|p| Path::new(p))
        .map_err(|_| negate_errno(EINVAL))
}

fn build_operations() -> fuse::fuse_operations {
    fuse::fuse_operations {
        #[cfg(any(feature = "full", feature = "getattr"))]
        getattr: Some(getattr),
        #[cfg(any(feature = "full", feature = "readlink"))]
        readlink: Some(readlink),
        #[cfg(any(feature = "full", feature = "mkdir"))]
        mkdir: Some(mkdir),
        #[cfg(any(feature = "full", feature = "unlink"))]
        unlink: Some(unlink),
        #[cfg(any(feature = "full", feature = "rmdir"))]
        rmdir: Some(rmdir),
        #[cfg(any(feature = "full", feature = "symlink"))]
        symlink: Some(symlink),
        #[cfg(any(feature = "full", feature = "rename"))]
        rename: Some(rename),
        #[cfg(any(feature = "full", feature = "link"))]
        link: Some(link),
        #[cfg(any(feature = "full", feature = "chmod"))]
        chmod: Some(chmod),
        #[cfg(any(feature = "full", feature = "chown"))]
        chown: Some(chown),
        #[cfg(any(feature = "full", feature = "truncate"))]
        truncate: Some(truncate),
        #[cfg(any(feature = "full", feature = "open"))]
        open: Some(open),
        #[cfg(any(feature = "full", feature = "read"))]
        read: Some(read),
        #[cfg(any(feature = "full", feature = "write"))]
        write: Some(write),
        #[cfg(any(feature = "full", feature = "statfs"))]
        statfs: Some(statfs), // not fine
        #[cfg(any(feature = "full", feature = "flush"))]
        flush: Some(flush),
        #[cfg(any(feature = "full", feature = "release"))]
        release: Some(release),
        #[cfg(any(feature = "full", feature = "fsync"))]
        fsync: Some(fsync),
        #[cfg(any(feature = "full", feature = "opendir"))]
        opendir: Some(opendir), // not fine
        #[cfg(any(feature = "full", feature = "readdir"))]
        readdir: Some(readdir),
        #[cfg(any(feature = "full", feature = "fsyncdir"))]
        fsyncdir: Some(fsyncdir),
        #[cfg(any(feature = "full", feature = "releasedir"))]
        releasedir: Some(releasedir),
        #[cfg(any(feature = "full", feature = "init"))]
        init: Some(init),
        #[cfg(any(feature = "full", feature = "destroy"))]
        destroy: Some(destroy),
        #[cfg(any(feature = "full", feature = "access"))]
        access: Some(access),
        #[cfg(any(feature = "full", feature = "create"))]
        create: Some(create), // ok
        #[cfg(any(feature = "full", feature = "ftruncate"))]
        ftruncate: Some(ftruncate),
        #[cfg(any(feature = "full", feature = "fgetattr"))]
        fgetattr: Some(fgetattr),
        // TODO: lock, utimens, bmap, ext_metadata
        ..Default::default()
    }
}

fn negate_errno(err: Errno) -> c_int {
    let e = err as c_int;
    if e < 0 {
        e
    } else {
        -e
    }
}

unsafe fn setup_fs(fs: &'static mut dyn Filesystem) -> Result<(), Error> {
    FS.set(RwLock::new(FilesystemImpl(fs)))
        .map_err(|_| Error::AlreadyMountedError)
}

unsafe fn get_fs<'a>() -> RwLockReadGuard<'a, FilesystemImpl> {
    FS.get()
        .expect("fetching FS")
        .read()
        .expect("acquiring read lock")
}

unsafe fn get_mut_fs<'a>() -> &'a mut FilesystemImpl {
    FS.get_mut()
        .expect("fetching mut FS")
        .get_mut()
        .expect("acquiring mut lock")
}

struct FilesystemImpl(&'static mut dyn Filesystem);

impl Deref for FilesystemImpl {
    type Target = &'static mut dyn Filesystem;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FilesystemImpl {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{filesystem::FileStat, Result};
    use nix::errno::Errno::ENOENT;
    use std::io::prelude::Write;
    use std::{ffi::OsStr, mem};

    static mut DUMMY_FS: DummyFS = DummyFS {};
    const FOO_PATH: &str = "/path/to/foo.txt";
    const BAR_PATH: &str = "/path/to/bar.xyz";

    #[test]
    fn test_build_path() {
        assert_eq!(
            unsafe { build_path(std::ptr::null()) }.err(),
            Some(negate_errno(EINVAL))
        );

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { build_path(ptr) }.ok(), Some(Path::new(FOO_PATH)));
    }

    #[test]
    fn test_getattr() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let stat = std::ptr::null_mut();
        assert_eq!(unsafe { getattr(ptr, stat) }, negate_errno(EINVAL));

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut stat = mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { getattr(ptr, stat.as_mut_ptr()) },
            negate_errno(ENOENT)
        );

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut stat = mem::MaybeUninit::uninit();
        unsafe {
            assert_eq!(getattr(ptr, stat.as_mut_ptr()), 0);

            let stat = stat.assume_init();
            assert_eq!(stat.st_nlink, 3);
        };
    }

    #[test]
    fn test_readlink() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let len = 13; // BAR_PATH - extension + nul byte
        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(
            unsafe { readlink(ptr, std::ptr::null_mut(), len) },
            negate_errno(EINVAL)
        );

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut buf = mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { readlink(ptr, buf.as_mut_ptr(), len) },
            negate_errno(ENOENT)
        );

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut vec = Vec::with_capacity(len);
        unsafe {
            vec.set_len(len);
            let buf = CString::from_vec_unchecked(vec).into_raw();
            assert_eq!(readlink(ptr, buf, len), 0);

            let got = CString::from_raw(buf);
            assert_eq!(got.to_bytes_with_nul(), b"/path/to/bar\0");
        };
    }

    #[test]
    fn test_mkdir() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mode: libc::mode_t = libc::S_IFDIR | 0o755;
        assert_eq!(unsafe { mkdir(ptr, mode) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { mkdir(ptr, mode) }, 0);
    }

    #[test]
    fn test_unlink() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { unlink(ptr) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { unlink(ptr) }, 0);
    }

    #[test]
    fn test_rmdir() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { rmdir(ptr) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { rmdir(ptr) }, 0);
    }

    #[test]
    fn test_symlink() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let src = CString::new(BAR_PATH).unwrap();
        let src_ptr = src.as_ptr();
        let dst = CString::new(FOO_PATH).unwrap();
        let dst_ptr = dst.as_ptr();
        assert_eq!(unsafe { symlink(src_ptr, dst_ptr) }, negate_errno(ENOENT));

        let src = CString::new(FOO_PATH).unwrap();
        let src_ptr = src.as_ptr();
        assert_eq!(unsafe { symlink(src_ptr, dst_ptr) }, 0);
    }

    #[test]
    fn test_rename() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let from = CString::new(BAR_PATH).unwrap();
        let from_ptr = from.as_ptr();
        let to = CString::new(FOO_PATH).unwrap();
        let to_ptr = to.as_ptr();
        assert_eq!(unsafe { rename(from_ptr, to_ptr) }, negate_errno(ENOENT));

        let from = CString::new(FOO_PATH).unwrap();
        let from_ptr = from.as_ptr();
        assert_eq!(unsafe { rename(from_ptr, to_ptr) }, 0);
    }

    #[test]
    fn test_link() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let src = CString::new(BAR_PATH).unwrap();
        let src_ptr = src.as_ptr();
        let dst = CString::new(FOO_PATH).unwrap();
        let dst_ptr = dst.as_ptr();
        assert_eq!(unsafe { link(src_ptr, dst_ptr) }, negate_errno(ENOENT));

        let src = CString::new(FOO_PATH).unwrap();
        let src_ptr = src.as_ptr();
        assert_eq!(unsafe { link(src_ptr, dst_ptr) }, 0);
    }

    #[test]
    fn test_chmod() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mode: libc::mode_t = libc::S_IFDIR | 0o755;
        assert_eq!(unsafe { chmod(ptr, mode) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { chmod(ptr, mode) }, 0);
    }

    #[test]
    fn test_chown() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let uid = 123;
        let gid = 456;

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { chown(ptr, uid, gid) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { chown(ptr, uid, gid) }, 0);
    }

    #[test]
    fn test_truncate() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let offset = 128;
        assert_eq!(unsafe { truncate(ptr, offset) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(unsafe { truncate(ptr, offset) }, 0);
    }

    #[test]
    fn test_open() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        assert_eq!(
            unsafe { open(ptr, std::ptr::null_mut()) },
            negate_errno(EINVAL)
        );

        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut fi = mem::MaybeUninit::uninit();
        assert_eq!(unsafe { open(ptr, fi.as_mut_ptr()) }, negate_errno(ENOENT));

        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut fi = mem::MaybeUninit::uninit();
        unsafe {
            assert_eq!(open(ptr, fi.as_mut_ptr()), 0);

            let fi = fi.assume_init();
            assert_eq!(fi.direct_io(), 1);
        }
    }

    #[test]
    fn test_read() {
        unsafe { setup_test_fs(&mut DUMMY_FS) };

        let len = 8;
        let offset = 0;

        // Invalid buffer: null
        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut fi = mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { read(ptr, std::ptr::null_mut(), len, offset, fi.as_mut_ptr()) },
            negate_errno(EINVAL)
        );

        // Wrong path
        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut buf = mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { read(ptr, buf.as_mut_ptr(), len, offset, fi.as_mut_ptr()) },
            negate_errno(ENOENT)
        );

        // Wrong path
        let p = CString::new(BAR_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut buf = mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { read(ptr, buf.as_mut_ptr(), len, offset, fi.as_mut_ptr()) },
            negate_errno(ENOENT)
        );

        // Truncate if fs wrote more than specified len in the buffer.
        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut vec = Vec::with_capacity(len);
        unsafe {
            vec.set_len(len);
            let buf = CString::from_vec_unchecked(vec).into_raw();

            assert_eq!(read(ptr, buf, len, offset, fi.as_mut_ptr()), len as _);

            let got = CString::from_raw(buf);
            assert_eq!(got.to_bytes_with_nul(), b"Hello Wo\0");
        }

        // Returns actual bytes read if fs read less than specified len. EOF case.
        let p = CString::new(FOO_PATH).unwrap();
        let ptr = p.as_ptr();
        let mut vec = Vec::with_capacity(len);
        unsafe {
            vec.set_len(len);
            let buf = CString::from_vec_unchecked(vec).into_raw();

            assert_eq!(read(ptr, buf, 2 * len, offset, fi.as_mut_ptr()), 12);

            let got = CString::from_raw(buf);
            assert_eq!(got.to_bytes_with_nul(), b"Hello World!\0");
        }
    }

    #[allow(unused_must_use)]
    unsafe fn setup_test_fs(fs: &'static mut dyn Filesystem) {
        setup_fs(fs);
    }

    struct DummyFS;

    impl Filesystem for DummyFS {
        fn metadata(&self, path: &Path) -> Result<FileStat> {
            if path.ends_with("foo.txt") {
                let mut fstat = FileStat::new();
                fstat.st_nlink = 3;
                Ok(fstat)
            } else {
                Err(ENOENT)
            }
        }

        fn read_link(&self, path: &Path) -> Result<&OsStr> {
            if path.ends_with("foo.txt") {
                Ok(Path::new(BAR_PATH).as_os_str())
            } else {
                Err(ENOENT)
            }
        }

        fn create_dir(&mut self, path: &Path, _mode: Mode) -> Result<()> {
            if path.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn remove_file(&mut self, path: &Path) -> Result<()> {
            if path.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn remove_dir(&mut self, path: &Path) -> Result<()> {
            if path.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn symlink(&mut self, src: &Path, _dst: &Path) -> Result<()> {
            if src.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn rename(&mut self, from: &Path, _to: &Path) -> Result<()> {
            if from.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn hard_link(&mut self, src: &Path, _dst: &Path) -> Result<()> {
            if src.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn set_permissions(&mut self, path: &Path, _mode: Mode) -> Result<()> {
            if path.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn set_owner(&mut self, path: &Path, _uid: Uid, _gid: Gid) -> Result<()> {
            if path.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn set_len(&mut self, path: &Path, _len: u64) -> Result<()> {
            if path.ends_with("foo.txt") {
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn open(&mut self, path: &Path, file_info: &mut OpenFileInfo) -> Result<()> {
            if path.ends_with("foo.txt") {
                file_info.set_direct_io(true);
                Ok(())
            } else {
                Err(ENOENT)
            }
        }

        fn read(
            &mut self,
            path: &Path,
            buf: &mut Vec<u8>,
            _offset: u64,
            _file_info: FileInfo,
        ) -> Result<usize> {
            if path.ends_with("foo.txt") {
                buf.write(b"Hello World!").map_err(|_| Errno::EFAULT)
            } else {
                Err(ENOENT)
            }
        }
    }
}
