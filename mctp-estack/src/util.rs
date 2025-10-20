/// Takes a `usize` from a build-time environment variable.
///
/// If unset, the default is used. Can be used in a const context.
macro_rules! get_build_var {
    ($name:literal, $default:expr) => {{
        match option_env!($name) {
            Some(v) => {
                let Ok(v) = usize::from_str_radix(v, 10) else {
                    // concat! because const format_args isn't stable
                    panic!(concat!(
                        "Bad value for environment variable ",
                        $name
                    ));
                };
                v
            }
            None => $default,
        }
    }};
}

/// A reader to read a vector of byte slices
///
#[derive(Debug)]
pub struct VectorReader {
    /// The index of the current slice
    ///
    /// Set to `vector.len()` when exhausted.
    slice_index: usize,
    /// The index in the current slice
    ///
    /// E.g. the element to be read next.
    current_slice_offset: usize,
}

impl VectorReader {
    /// Create a new reader
    pub fn new() -> Self {
        VectorReader {
            slice_index: 0,
            current_slice_offset: 0,
        }
    }
    /// Read `dest.len()` bytes from `src` into `dest`, returning how many bytes were read
    ///
    /// Returns a [VectorReaderError] when the current position is out of range for `src`.
    ///
    /// The same `src` buffer has to be passed to subsequent calls to `read()`.
    /// Changing the vector is undefined behaviour.
    pub fn read(
        &mut self,
        src: &[&[u8]],
        dest: &mut [u8],
    ) -> Result<usize, VectorReaderError> {
        let mut i = 0;
        while i < dest.len() {
            if self.is_exhausted(src)? {
                return Ok(i);
            }

            let slice = &src[self.slice_index][self.current_slice_offset..];
            let n = slice.len().min(dest[i..].len());
            dest[i..i + n].copy_from_slice(&slice[..n]);
            i += n;
            self.increment_index(src, n);
        }
        Ok(i)
    }
    /// Checks if `src` has been read to the end
    ///
    /// Returns a [VectorReaderError] when the current position is out of range for `src`.
    ///
    /// _Note:_ Might return a `Ok` even if the `src` vector changed between calls.
    pub fn is_exhausted(
        &self,
        src: &[&[u8]],
    ) -> Result<bool, VectorReaderError> {
        if src.len() == self.slice_index {
            return Ok(true);
        }
        // This shlould only occur if the caller passed varying vectors
        src.get(self.slice_index).ok_or(VectorReaderError)?;
        Ok(false)
    }
    /// Increment the index by `n`, panic if out ouf bounds
    ///
    /// If this exhausts the vector exactly, the index is incremented to `vector[vector.len()][0]`
    fn increment_index(&mut self, vector: &[&[u8]], n: usize) {
        let mut n = n;
        loop {
            if vector[self.slice_index]
                .get(self.current_slice_offset + n)
                .is_some()
            {
                // If we can index the current slice at offset + n just increment offset and return
                self.current_slice_offset += n;
                return;
            } else {
                // Substract what has been read from the current slice, then increment to next slice
                n -=
                    vector[self.slice_index][self.current_slice_offset..].len();
                self.slice_index += 1;
                self.current_slice_offset = 0;
                if self.slice_index == vector.len() {
                    // return when the end of the vector is reached
                    debug_assert_eq!(n, 0);
                    return;
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct VectorReaderError;

#[cfg(test)]
mod tests {
    #[test]
    fn test_vector_reader() {
        use super::VectorReader;
        let mut reader = VectorReader::new();
        let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5], &[6, 7, 8, 9]];

        // Test reading a vector partially
        let mut dest = [0; 4];
        let n = reader.read(vector, &mut dest).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&dest, &[1, 2, 3, 4]);

        // Test reading all remaining elements into a larger than necessary destination
        let mut dest = [0; 6];
        let n = reader.read(vector, &mut dest).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&dest[..5], &[5, 6, 7, 8, 9]);

        assert!(reader
            .is_exhausted(vector)
            .expect("Vector should be exhausted"));

        // Test reading to end in one pass
        let mut reader = VectorReader::new();
        let vector: &[&[u8]] = &[&[1, 2, 3], &[4]];

        let mut dest = [0; 4];
        let n = reader.read(vector, &mut dest).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&dest, &[1, 2, 3, 4]);

        assert!(reader
            .is_exhausted(vector)
            .expect("Vector should be exhausted"));
    }
}
