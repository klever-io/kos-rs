// serde-big-array doesn't allow documentation of its generated structure
#![allow(missing_docs)]
use core::array::TryFromSliceError;
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::convert::TryFrom;
use core::ops::{Deref, DerefMut};
use core::{fmt, str};
use hex::{FromHex, FromHexError};

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "random")]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

use crate::hex_val;

macro_rules! key {
    ($i:ident, $s:expr) => {
        #[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        /// atomic array type.
        #[repr(transparent)]
        pub struct $i([u8; $s]);

        key_methods!($i, $s);

        #[cfg(feature = "random")]
        impl Distribution<$i> for Standard {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> $i {
                $i(rng.gen())
            }
        }
    };
}

macro_rules! key_with_big_array {
    ($i:ident, $s:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        /// atomic type.
        #[repr(transparent)]
        pub struct $i([u8; $s]);

        key_methods!($i, $s);

        impl Default for $i {
            fn default() -> $i {
                $i([0u8; $s])
            }
        }

        #[cfg(feature = "random")]
        impl Distribution<$i> for Standard {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> $i {
                let mut bytes = $i::default();

                rng.fill_bytes(bytes.as_mut());

                bytes
            }
        }
    };
}

macro_rules! key_methods {
    ($i:ident, $s:expr) => {
        impl $i {
            /// Memory length of the type
            pub const LEN: usize = $s;

            /// Bytes constructor.
            pub const fn new(bytes: [u8; $s]) -> Self {
                Self(bytes)
            }

            /// Zeroes bytes constructor.
            pub const fn zeroed() -> $i {
                $i([0; $s])
            }

            #[allow(unsafe_code)]
            /// Add a conversion from arbitrary slices into owned
            ///
            /// # Safety
            ///
            /// This function will not panic if the length of the slice is smaller than
            /// `Self::LEN`. Instead, it will cause undefined behavior and read random disowned
            /// bytes
            pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
                $i($crate::bytes::from_slice_unchecked(bytes))
            }

            /// Copy-free reference cast
            /// # Safety
            /// Assumes the type is `repr[transparent]`.
            pub fn from_bytes_ref_checked(bytes: &[u8]) -> Option<&Self> {
                let bytes: &[u8; $s] = bytes.get(..$s)?.try_into().ok()?;
                Some(Self::from_bytes_ref(bytes))
            }

            /// Copy-free reference cast
            /// # Safety
            /// Assumes the type is `repr[transparent]`.
            pub fn from_bytes_ref(bytes: &[u8; $s]) -> &Self {
                // The interpreter will frequently make references to keys and values using
                // logically checked slices.
                //
                // This function will save unnecessary copy to owned slices for the interpreter
                // access
                #[allow(unsafe_code)]
                unsafe {
                    &*(bytes.as_ptr() as *const Self)
                }
            }

            /// The memory size of the type by the method.
            pub const fn size(&self) -> usize {
                Self::LEN
            }
        }

        #[cfg(feature = "random")]
        impl rand::Fill for $i {
            fn try_fill<R: rand::Rng + ?Sized>(&mut self, rng: &mut R) -> Result<(), rand::Error> {
                rng.fill_bytes(self.as_mut());

                Ok(())
            }
        }

        impl Deref for $i {
            type Target = [u8; $s];

            fn deref(&self) -> &[u8; $s] {
                &self.0
            }
        }

        impl Borrow<[u8; $s]> for $i {
            fn borrow(&self) -> &[u8; $s] {
                &self.0
            }
        }

        impl BorrowMut<[u8; $s]> for $i {
            fn borrow_mut(&mut self) -> &mut [u8; $s] {
                &mut self.0
            }
        }

        impl DerefMut for $i {
            fn deref_mut(&mut self) -> &mut [u8; $s] {
                &mut self.0
            }
        }

        impl AsRef<[u8]> for $i {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsMut<[u8]> for $i {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }

        impl From<[u8; $s]> for $i {
            fn from(bytes: [u8; $s]) -> Self {
                Self(bytes)
            }
        }

        impl From<$i> for [u8; $s] {
            fn from(salt: $i) -> [u8; $s] {
                salt.0
            }
        }

        impl TryFrom<&[u8]> for $i {
            type Error = TryFromSliceError;

            fn try_from(bytes: &[u8]) -> Result<$i, TryFromSliceError> {
                <[u8; $s]>::try_from(bytes).map(|b| b.into())
            }
        }

        impl FromHex for $i {
            type Error = FromHexError;

            fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, FromHexError> {
                let b: [u8; Self::LEN] = FromHex::from_hex(hex)?;
                b.try_into().map_err(|_| FromHexError::InvalidStringLength)
            }
        }

        impl fmt::LowerHex for $i {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    write!(f, "0x")?
                }

                match f.width() {
                    Some(w) if w > 0 => self.0.chunks(2 * Self::LEN / w).try_for_each(|c| {
                        write!(f, "{:02x}", c.iter().fold(0u8, |acc, x| acc ^ x))
                    }),

                    _ => self.0.iter().try_for_each(|b| write!(f, "{:02x}", &b)),
                }
            }
        }

        impl fmt::UpperHex for $i {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    write!(f, "0x")?
                }

                match f.width() {
                    Some(w) if w > 0 => self.0.chunks(2 * Self::LEN / w).try_for_each(|c| {
                        write!(f, "{:02X}", c.iter().fold(0u8, |acc, x| acc ^ x))
                    }),

                    _ => self.0.iter().try_for_each(|b| write!(f, "{:02X}", &b)),
                }
            }
        }

        impl fmt::Debug for $i {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                <Self as fmt::LowerHex>::fmt(&self, f)
            }
        }

        impl fmt::Display for $i {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                <Self as fmt::LowerHex>::fmt(&self, f)
            }
        }

        impl str::FromStr for $i {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                const ERR: &str = "Invalid encoded byte";

                let alternate = s.starts_with("0x");

                let mut b = s.bytes();
                let mut ret = $i::zeroed();

                if alternate {
                    b.next();
                    b.next();
                }

                for r in ret.as_mut() {
                    let h = b.next().and_then(hex_val).ok_or(ERR)?;
                    let l = b.next().and_then(hex_val).ok_or(ERR)?;

                    *r = h << 4 | l;
                }

                Ok(ret)
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $i {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use alloc::format;
                serializer.serialize_str(&format!("{:x}", &self))
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $i {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;
                let s: &str = serde::Deserialize::deserialize(deserializer)?;
                s.parse().map_err(D::Error::custom)
            }
        }
    };
}

key!(Bytes32, 32);
key_with_big_array!(Bytes64, 64);
