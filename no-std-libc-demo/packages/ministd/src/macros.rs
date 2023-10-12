#[macro_export]
macro_rules! print {
    ($format_string:literal) => {{
        let mut stream = $crate::io::Stream::STDOUT;
        $crate::io::Write::write_all(&mut stream, $format_string.as_bytes())
    }};
    ($format_string:literal, $($args:tt)*) => {{
        let mut stream = $crate::io::Stream::STDOUT;
        $crate::io::Write::write_fmt(&mut stream, format_args!($format_string, $($args)*))
    }};
}

#[macro_export]
macro_rules! println {
    ($format_string:literal) => {{
        let mut stream = $crate::io::Stream::STDOUT;
        $crate::io::Write::write_all(&mut stream, concat!($format_string, "\n").as_bytes())
    }};
    ($format_string:literal, $($args:tt)*) => {{
        let mut stream = $crate::io::Stream::STDOUT;
        $crate::io::Write::write_fmt(&mut stream, format_args!(concat!($format_string, "\n"), $($args)*))
    }};
}

#[macro_export]
macro_rules! eprint {
    ($format_string:literal) => {{
        let mut stream = $crate::io::Stream::STDERR;
        $crate::io::Write::write_all(&mut stream, $format_string.as_bytes())
    }};
    ($format_string:literal, $($args:tt)*) => {{
        let mut stream = $crate::io::Stream::STDERR;
        $crate::io::Write::write_fmt(&mut stream, format_args!($format_string, $($args)*))
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($format_string:literal) => {{
        let mut stream = $crate::io::Stream::STDERR;
        $crate::io::Write::write_all(&mut stream, concat!($format_string, "\n").as_bytes())
    }};
    ($format_string:literal, $($args:tt)*) => {{
        let mut stream = $crate::io::Stream::STDERR;
        $crate::io::Write::write_fmt(&mut stream, format_args!(concat!($format_string, "\n"), $($args)*))
    }};
}

#[macro_export]
macro_rules! entry {
    ($rust_main:ident) => {
        // `const` wrapper makes the inner function uncallable from the caller's scope
        const _: () = {
            #[export_name = "main"]
            // prefix name with underscores to avoid colliding with `$rust_main`
            extern "C" fn __extern_c_main() -> ! {
                let status = match $rust_main() {
                    Ok(()) => 0,
                    Err(e) => {
                        let _ = $crate::eprintln!("{:?}", e);
                        1
                    }
                };
                $crate::process::exit(status)
            }
        };
    };
}

#[macro_export]
macro_rules! dbg {
    () => {
        let _ = $crate::eprintln!("[{}:{}]", core::file!(), core::line!());
    };
    ($val:expr $(,)?) => {
        match $val {
            tmp => {
                let _ = $crate::eprintln!(
                    "[{}:{}] {} = {:#?}",
                    core::file!(),
                    core::line!(),
                    core::stringify!($val),
                    &tmp
                );

                tmp
            }

        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
