#[macro_use]
extern crate bitflags;
extern crate nix;

use nix::errno::Errno;

#[macro_use]
mod macros;

pub mod filesystem;

pub use crate::filesystem::Filesystem;

pub type Result<T> = std::result::Result<T, Errno>;
