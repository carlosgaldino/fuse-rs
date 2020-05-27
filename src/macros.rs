// Copied from nix: https://github.com/nix-rust/nix/blob/d950c481abe5fb11cdbd648c67c8022c6c209664/src/macros.rs#L41-L61
macro_rules! libc_bitflags {
    (
        $(#[$outer:meta])*
        pub struct $BitFlags:ident: $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                    $Flag:ident $(as $cast:ty)*;
            )+
        }
    ) => {
        bitflags! {
            $(#[$outer])*
            pub struct $BitFlags: $T {
                $(
                    $(#[$inner $($args)*])*
                        const $Flag = libc::$Flag $(as $cast)*;
                )+
            }
        }
    };
}

macro_rules! unit_op {
    ($fn:expr) => {{
        match $fn {
            Ok(_) => 0,
            Err(err) => negate_errno(err),
        }
    }};
}
