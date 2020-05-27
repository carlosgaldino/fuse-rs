#[macro_use]
extern crate bitflags;
extern crate cfg_if;
extern crate nix;

use nix::errno::Errno;

#[macro_use]
mod macros;

pub mod filesystem;
mod operations;

pub use crate::filesystem::Filesystem;
pub use crate::operations::{mount, Error};

pub type Result<T> = std::result::Result<T, Errno>;
