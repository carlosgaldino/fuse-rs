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
        match FS.set(RwLock::new(FilesystemImpl(filesystem))) {
            Ok(_) => {}
            Err(_) => return Err(Error::AlreadyMountedError),
        };

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
    match build_path(p) {
        Ok(path) => match get_fs().metadata(path) {
            Ok(file_stat) => file_stat.fill(stat),
            Err(err) => negate_errno(err),
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn readlink(p: *const c_char, buffer: *mut c_char, len: usize) -> c_int {
    match build_path(p) {
        Ok(path) => match get_fs().read_link(path) {
            Ok(path) => {
                std::ptr::copy_nonoverlapping(
                    CStr::from_bytes_with_nul_unchecked(path.as_bytes()).as_ptr(),
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
    let mut buf = Vec::with_capacity(len);
    match build_path(p) {
        Ok(path) => match get_mut_fs().read(path, &mut buf, offset as _, FileInfo::from_raw(fi)) {
            Ok(length) => {
                std::ptr::copy_nonoverlapping(
                    CString::from_vec_unchecked(buf).as_ptr(),
                    buffer,
                    length,
                );
                length as _
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
    CStr::from_ptr(p)
        .to_str()
        .map(|p| Path::new(p))
        .map_err(|_| negate_errno(EINVAL))
}

fn build_operations() -> fuse::fuse_operations {
    fuse::fuse_operations {
        getattr: Some(getattr),
        readlink: Some(readlink),
        mkdir: Some(mkdir),
        unlink: Some(unlink),
        rmdir: Some(rmdir),
        symlink: Some(symlink),
        rename: Some(rename),
        link: Some(link),
        chmod: Some(chmod),
        chown: Some(chown),
        truncate: Some(truncate),
        open: Some(open),
        read: Some(read),
        write: Some(write),
        statfs: Some(statfs), // not fine
        flush: Some(flush),
        release: Some(release),
        fsync: Some(fsync),
        opendir: Some(opendir), // not fine
        readdir: Some(readdir),
        fsyncdir: Some(fsyncdir),
        releasedir: Some(releasedir),
        init: Some(init),
        destroy: Some(destroy),
        access: Some(access),
        create: Some(create), // ok
        ftruncate: Some(ftruncate),
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

unsafe fn get_fs<'a>() -> RwLockReadGuard<'a, FilesystemImpl> {
    FS.get().expect("fetching fs").read().expect("read fs")
}

unsafe fn get_mut_fs<'a>() -> &'a mut FilesystemImpl {
    FS.get_mut()
        .expect("fetching FS")
        .get_mut()
        .expect("get mut lock")
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
