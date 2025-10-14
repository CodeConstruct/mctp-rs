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

/// Copy data from a vectored src to dest
///
/// Copies `dest.len()` bytes from payload to dest,
/// starting after `offset` bytes.
///
/// ## Panics
///
/// This function will panic when not enough bytes are available to fill dest.
/// Total size of `payload` has to be `atleast dest.len()` + `offset`.
pub fn copy_vectored(src: &[&[u8]], offset: usize, dest: &mut [u8]) {
    let mut i = 0;

    while i < dest.len() {
        let payload_index = i + offset;
        let next = get_sub_slice(src, payload_index);
        let remaining = dest.len() - i;
        if remaining > next.len() {
            dest[i..(i + next.len())].copy_from_slice(next);
            i += next.len();
        } else {
            dest[i..].copy_from_slice(&next[..remaining]);
            return;
        }
    }
}

/// Get a slice of `vector` indexed by `offset`
///
/// The `offset` is the absolute byte index.
/// The returned slice is the remaining sub slice starting at `offset`.
///
/// ## Panics
///
/// Will panic when offset is larger than the size of `vector`.
///
/// ## Example
/// ```ignore
/// # use mctp_estack::fragment::get_slice;
/// let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5, 6]];
///
/// let slice = get_slice(vector, 4);
///
/// assert_eq!(slice, &[5, 6]);
/// ```
pub fn get_sub_slice<'a>(vector: &'a [&[u8]], offset: usize) -> &'a [u8] {
    let mut i = offset;
    for slice in vector {
        if i >= slice.len() {
            i -= slice.len();
        } else {
            return &slice[i..];
        }
    }
    panic!("offset for vector out of bounds");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_slice() {
        use super::get_sub_slice;
        let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5, 6], &[7, 8, 9]];
        let slice = get_sub_slice(vector, 4);
        assert_eq!(slice, &[5, 6]);
        let slice = get_sub_slice(vector, 0);
        assert_eq!(slice, &[1, 2, 3]);
        let slice = get_sub_slice(vector, 3);
        assert_eq!(slice, &[4, 5, 6]);
    }
    #[test]
    fn test_copy_vectored() {
        use super::copy_vectored;
        let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5], &[6, 7, 8, 9]];

        let mut dest = [0; 6];
        copy_vectored(vector, 1, &mut dest);
        assert_eq!(&dest, &[2, 3, 4, 5, 6, 7]);

        let mut dest = [0; 5];
        copy_vectored(vector, 4, &mut dest);
        assert_eq!(&dest, &[5, 6, 7, 8, 9]);

        let mut dest = [0; 9];
        copy_vectored(vector, 0, &mut dest);
        assert_eq!(&dest, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let vector: &[&[u8]] = &[&[1, 2, 3]];

        let mut dest = [0; 1];
        copy_vectored(vector, 2, &mut dest);
        assert_eq!(&dest, &[3]);
    }
}
