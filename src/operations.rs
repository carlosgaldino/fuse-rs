extern crate once_cell;

use crate::filesystem::Filesystem;
use libc::{c_char, c_int, stat};
use libfuse_sys as ffi;
use nix::{
    errno::Errno::{self, EINVAL},
    sys::stat::Mode,
};
use once_cell::sync::OnceCell;
use std::{
    ffi::{CStr, CString, OsString},
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

        match ffi::fuse::fuse_main(
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

unsafe extern "C" fn mkdir(p: *const c_char, mode: libc::mode_t) -> c_int {
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

unsafe fn build_path<'a>(p: *const c_char) -> Result<&'a Path, c_int> {
    CStr::from_ptr(p)
        .to_str()
        .map(|p| Path::new(p))
        .map_err(|_| negate_errno(EINVAL))
}

fn build_operations() -> ffi::fuse::fuse_operations {
    ffi::fuse::fuse_operations {
        getattr: Some(getattr),
        readlink: Some(readlink),
        mkdir: Some(mkdir),
        unlink: Some(unlink),
        rmdir: Some(rmdir),
        symlink: Some(symlink),
        rename: Some(rename),
        link: Some(link),
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
