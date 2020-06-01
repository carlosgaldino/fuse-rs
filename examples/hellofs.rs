extern crate fuse_rs;
extern crate nix;

use fuse_rs::{
    fs::{DirEntry, FileInfo, FileStat, OpenFileInfo},
    Filesystem,
};
use nix::{errno::Errno, fcntl::OFlag, sys::stat::SFlag};
use std::{ffi::OsString, io::Read, path::Path};

static HELLO_WORLD: &str = "Hello World!\n";

struct HelloFS;

impl Filesystem for HelloFS {
    fn metadata(&self, path: &Path) -> fuse_rs::Result<FileStat> {
        let mut stat = FileStat::new();
        match path.to_str().expect("path") {
            "/" => {
                stat.st_mode = SFlag::S_IFDIR.bits() | 0o755;
                stat.st_nlink = 3;
            }
            "/hello.txt" => {
                stat.st_mode = SFlag::S_IFREG.bits() | 0o644;
                stat.st_nlink = 1;
                stat.st_size = HELLO_WORLD.len() as _;
            }
            _ => return Err(Errno::ENOENT),
        }
        Ok(stat)
    }

    fn read_dir(
        &mut self,
        path: &Path,
        _offset: u64,
        _file_info: FileInfo,
    ) -> fuse_rs::Result<Vec<DirEntry>> {
        if path != Path::new("/") {
            return Err(Errno::ENOENT);
        }

        Ok(vec![".", "..", "hello.txt"]
            .into_iter()
            .map(|n| DirEntry {
                name: OsString::from(n),
                metadata: None,
                offset: None,
            })
            .collect())
    }

    fn open(&mut self, path: &Path, file_info: &mut OpenFileInfo) -> fuse_rs::Result<()> {
        if path != Path::new("/hello.txt") {
            return Err(Errno::ENOENT);
        }

        if (file_info.flags().unwrap_or(OFlag::empty()) & OFlag::O_ACCMODE) != OFlag::O_RDONLY {
            return Err(Errno::EACCES);
        }

        Ok(())
    }

    fn read(
        &mut self,
        path: &Path,
        buf: &mut [u8],
        offset: u64,
        _file_info: FileInfo,
    ) -> fuse_rs::Result<usize> {
        if path != Path::new("/hello.txt") {
            return Err(Errno::ENOENT);
        }

        let size = HELLO_WORLD.len() as u64;
        let mut cap = buf.len() as u64;
        if offset > size as _ {
            return Ok(0);
        }

        if offset + cap > size {
            cap = size - offset;
        }

        (&HELLO_WORLD.as_bytes()[offset as usize..cap as usize])
            .read(buf)
            .map_err(|e| Errno::from_i32(e.raw_os_error().expect("read error")))
    }
}

fn main() -> Result<(), fuse_rs::Error> {
    let opts = vec![
        OsString::from("-s"),
        OsString::from("-f"),
        OsString::from("-d"),
        OsString::from("-o"),
        OsString::from("volname=hello_world"),
        OsString::from("-o"),
        OsString::from("ro"),
    ];
    static mut FS: HelloFS = HelloFS {};
    unsafe {
        fuse_rs::mount(
            std::env::args_os().next().unwrap(),
            "./hello_fs",
            &mut FS,
            opts,
        )
    }
}
