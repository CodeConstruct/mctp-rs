// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2024 Code Construct
 */

/// Holds either an allocated `Vec` or borrowed slice.
#[derive(Debug)]
pub enum VecOrSlice<'a, V> {
    /// An allocated `std::Vec` buffer
    #[cfg(feature = "alloc")]
    Owned(Vec<V>),
    /// A borrowed slice
    Borrowed(&'a [V]),
}

impl<'a, V> core::ops::Deref for VecOrSlice<'a, V> {
    type Target = [V];
    fn deref(&self) -> &[V] {
        self.as_ref()
    }
}

impl<'a, V> AsRef<[V]> for VecOrSlice<'a, V> {
    fn as_ref(&self) -> &[V] {
        match self {
            #[cfg(feature = "alloc")]
            Self::Owned(v) => v.as_slice(),
            Self::Borrowed(s) => s,
        }
    }
}

#[cfg(feature = "alloc")]
impl<V> From<Vec<V>> for VecOrSlice<'static, V> {
    fn from(v: Vec<V>) -> Self {
        Self::Owned(v)
    }
}

impl<'a, V> From<&'a [V]> for VecOrSlice<'a, V> {
    fn from(v: &'a [V]) -> Self {
        Self::Borrowed(v)
    }
}

impl<'a, V> From<&'a mut [V]> for VecOrSlice<'a, V> {
    fn from(v: &'a mut [V]) -> Self {
        Self::Borrowed(v)
    }
}

