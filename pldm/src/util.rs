// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! Helper functions
use core::mem::size_of;

/// Holds either an allocated `Vec` or borrowed slice.
///
/// Can be constructed using `.into()` on a `Vec` (`std` feature) or `&[u8]` (always)
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

/// Writes into a borrowed mutable output buffer
///
/// Push methods return `Some(usize)` length on success, `None` on failure.
pub struct SliceWriter<'a> {
    s: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceWriter<'a> {
    /// Constructs a new `SliceWriter`
    pub fn new(s: &'a mut [u8]) -> Self {
        Self { s, pos: 0 }
    }

    /// Returns the number of bytes written
    pub fn written(&self) -> usize {
        debug_assert!(self.pos <= self.s.len());
        self.pos
    }

    /// Returns the written buffer
    pub fn done(&mut self) -> &mut [u8] {
        &mut self.s[..self.pos]
    }

    /// Pushes the provided slice into the output buffer
    #[must_use]
    pub fn push(&mut self, s: &[u8]) -> Option<usize> {
        let out = self.s.get_mut(self.pos..self.pos + s.len())?;
        out.copy_from_slice(s);
        self.pos += s.len();
        Some(s.len())
    }

    fn push_le<S>(&mut self, v: S) -> Option<usize>
    where
        S: num_traits::ToBytes,
    {
        self.push(v.to_le_bytes().as_ref())
    }

    /// Pushes a `u32` into the output buffer, little-endian
    ///
    /// Returns the length written or `None` on insufficient space.
    #[inline]
    #[must_use]
    pub fn push_le32(&mut self, v: u32) -> Option<usize> {
        self.push_le(v)
    }

    /// Pushes a `u16` into the output buffer, little-endian
    ///
    /// Returns the length written or `None` on insufficient space.
    #[inline]
    #[must_use]
    pub fn push_le16(&mut self, v: u16) -> Option<usize> {
        self.push_le(v)
    }

    /// Pushes a `u8` into the output buffer
    ///
    /// Returns the length written or `None` on insufficient space.
    #[inline]
    #[must_use]
    pub fn push_le8(&mut self, v: u8) -> Option<usize> {
        self.push_le(v)
    }

    /// Pushes data into the output buffer provided by a function.
    ///
    /// Returns the length written or `None` on insufficient space
    /// or if the `write` closure returns None.
    ///
    /// The closure must return `Some(length)`, with `length <= arg.len()`.
    /// It can return `None` on failure.
    #[must_use]
    pub fn push_with<F>(&mut self, write: F) -> Option<usize>
    where
        F: FnOnce(&mut [u8]) -> Option<usize>,
    {
        // write the data
        let out = self.s.get_mut(self.pos..)?;
        let l = write(out)?;
        if l > out.len() {
            return None;
        }
        self.pos += l;
        Some(l)
    }

    /// Pushes data into the output buffer provided by a function, with a length prefix.
    ///
    /// The `write` closure writes into the output buffer (with prefix space left),
    /// then the written length is written as prefix. The prefix is little endian,
    /// sized by the `S` parameter.
    ///
    /// Returns the total length written (including prefix) or `None` on insufficient space
    /// or if the `write` closure returns None.
    #[must_use]
    pub fn push_prefix_le<S, F>(&mut self, write: F) -> Option<usize>
    where
        S: num_traits::ToBytes + TryFrom<usize>,
        F: FnOnce(&mut [u8]) -> Option<usize>,
    {
        // Allow space for the length prefix
        let sz = size_of::<S>();
        if self.s.len() < sz {
            return None;
        }

        // Fill the data
        let out = self.s.get_mut(self.pos + sz..)?;
        let l = write(out)?;
        if l > out.len() {
            return None;
        }

        // Fill the length prefix. This writes to the original position.
        // Check it fits in the data type
        let ls = S::try_from(l).ok()?;
        self.s[self.pos..][..sz].copy_from_slice(ls.to_le_bytes().as_ref());

        self.pos += l + sz;
        debug_assert!(self.pos <= self.s.len());
        Some(l + sz)
    }
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, wrs: &str) -> core::fmt::Result {
        self.push(wrs.as_bytes()).ok_or(core::fmt::Error)?;
        Ok(())
    }
}

/// Helper to for converting `Option::None` to `PldmError::NoSpace`
///
/// `SliceWriter` returns `None` on failure. This trait converts
/// that failure to a `PldmError::NoSpace` for brevity.
pub trait NoneNoSpace<S> {
    /// Returns `PldmError::NoSpace` on failure
    fn space(self) -> crate::Result<S>;
}

impl<S> NoneNoSpace<S> for Option<S> {
    fn space(self) -> crate::Result<S> {
        self.ok_or(crate::PldmError::NoSpace)
    }
}

#[cfg(test)]
mod tests {

    use crate::*;

    #[test]
    fn slicewriter_prefix() {
        let mut x = [99u8; 20];
        let mut w = SliceWriter::new(&mut x);
        let l = w
            .push_prefix_le::<u16, _>(|m| {
                let mut ww = SliceWriter::new(m);
                ww.push(&[1, 2, 3, 4, 5])?;
                Some(ww.written())
            })
            .unwrap();
        assert_eq!(l, 7);
        let x = &x[..l];
        assert_eq!(x, [5, 0, 1, 2, 3, 4, 5]);

        let mut x = [99u8; 20];
        let mut w = SliceWriter::new(&mut x);
        let l = w
            .push_prefix_le::<u16, _>(|m| {
                m[0] = 1;
                Some(1)
            })
            .unwrap();
        assert_eq!(l, 3);
        let l = w
            .push_prefix_le::<u64, _>(|m| {
                m[0] = 3;
                Some(1)
            })
            .unwrap();
        assert_eq!(l, 9);

        let wr = w.written();
        let x = &x[..wr];
        assert_eq!(x, [1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3]);
    }

    #[test]
    fn slicewriter_nospace() {
        let mut x = [99u8; 3];
        let mut w = SliceWriter::new(&mut x);
        assert!(w.push_le32(9).is_none());
        assert_eq!(w.written(), 0);
        w.push_le16(0x1122).unwrap();
        assert_eq!(w.written(), 2);
        assert_eq!(w.done(), [0x22, 0x11]);
        assert_eq!(x, [0x22, 0x11, 99u8]);

        let mut w = SliceWriter::new(&mut []);
        assert!(w.push_le8(9).is_none());
        assert_eq!(w.written(), 0);
    }

    #[test]
    fn slicewriter() {
        let mut x = [99u8; 3];
        let mut w = SliceWriter::new(&mut x);
        let r = w.push_with(|_m| Some(20));
        assert!(r.is_none(), "Closure returns short length");

        let mut x = [99u8; 3];
        let mut w = SliceWriter::new(&mut x);
        let r = w.push_with(|m| {
            m[0] = 3;
            m[1] = 4;
            Some(2)
        });
        assert_eq!(r, Some(2));
        assert_eq!(x, [3, 4, 99u8]);
    }
}
