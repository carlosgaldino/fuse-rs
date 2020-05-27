extern crate once_cell;

use crate::filesystem::Filesystem;
use libc::{c_char, c_int, stat};
use libfuse_sys as ffi;
use nix::errno::Errno::{self, EINVAL};
use once_cell::sync::OnceCell;
use std::{
    ffi::{CStr, CString, OsString},
    ops::Deref,
    os::unix::ffi::OsStringExt,
    path::Path,
};

static FS: OnceCell<FilesystemImpl> = OnceCell::new();

#[derive(Debug)]
pub enum Error {
    AlreadyMountedError,
    MountError,
}

pub fn mount<P, I>(
    name: OsString,
    mountpoint: P,
    filesystem: &'static dyn Filesystem,
    args: I,
) -> Result<(), Error>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = OsString>,
{
    match FS.set(FilesystemImpl(filesystem)) {
        Ok(_) => {}
        Err(_) => return Err(Error::AlreadyMountedError),
    };

    unsafe {
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

unsafe extern "C" fn getattr(path: *const c_char, stat: *mut stat) -> c_int {
    let p = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return negate_errno(EINVAL),
    };

    match get_fs().metadata(Path::new(p)) {
        Ok(file_stat) => file_stat.fill(stat),
        Err(err) => negate_errno(err),
    }
}

fn build_operations() -> ffi::fuse::fuse_operations {
    ffi::fuse::fuse_operations {
        getattr: Some(getattr),
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

fn get_fs() -> &'static FilesystemImpl {
    FS.get().expect("fetching FS")
}

struct FilesystemImpl(&'static dyn Filesystem);

impl Deref for FilesystemImpl {
    type Target = &'static dyn Filesystem;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
