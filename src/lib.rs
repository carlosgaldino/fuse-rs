#[macro_use]
extern crate bitflags;
extern crate cfg_if;
extern crate nix;

use nix::errno::Errno;

#[macro_use]
mod macros;

pub mod fs;
mod operations;

pub use crate::fs::Filesystem;
pub use crate::operations::{mount, Error};

pub type Result<T> = std::result::Result<T, Errno>;
