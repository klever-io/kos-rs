pub mod bytes;
pub mod error;
pub mod hash;
pub mod number;
pub mod vectorize;

mod array_types;
pub use array_types::*;

pub(crate) const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'0'..=b'9' => Some(c - b'0'),
        _ => None,
    }
}

#[macro_export]
macro_rules! enum_thing {
    (
        enum $EnumName:ident {
            $($EnumVariant:ident($EnumType:ty)),* $(,)?
        }
    ) => {
        #[derive(serde::Serialize, Clone, Debug)]
        pub enum $EnumName {
            $($EnumVariant($EnumType),)*
        }

        $(
            impl TryFrom<$EnumName> for $EnumType {
                type Error = kos_types::error::Error;

                fn try_from(other: $EnumName) -> Result<Self, Self::Error> {
                    match other {
                        $EnumName::$EnumVariant(v) => Ok(v),
                        _ => Err(kos_types::error::Error::InvalidEnumVariant(stringify!($EnumName).to_string())),
                    }
                }
            }
        )*
    };
}
