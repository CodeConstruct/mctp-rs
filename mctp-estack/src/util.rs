/// Takes a `usize` from a build-time environment variable.
///
/// If unset, the default is used. Can be used in a const context.
#[macro_export]
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
