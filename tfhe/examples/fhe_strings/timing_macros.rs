/// A macro for displaying a timing result. The following elements are printed:
/// 1. the `$method` invoked,
/// 2. the initial clear string,
/// 3. the amount of null bytes padding used,
/// 4. the result of invoking `$method` on the clear string,
/// 5. the result of encrypt/run `$method`/decrypt,
/// 6. optional: when the returned type can be either "clear" or "encrypted" depending on the case,
///    a line is added to clarify the clear/encrypted status of the result.
#[macro_export]
macro_rules! display {
    ($method:ident, $clear_s:expr, $fhe_result:ident, $std_result:ident, $duration:expr) => {
        display!($method, $clear_s, 0, $fhe_result, $std_result, $duration)
    };
    ($method:ident, $clear_s:expr, $padding_zeros:expr, $fhe_result:ident, $std_result:ident, $duration:expr) => {
        display!(
            $method,
            $clear_s,
            $padding_zeros,
            $fhe_result,
            "",
            $std_result,
            $duration
        )
    };
    ($method:ident, $clear_s:expr, $padding_zeros:expr, $fhe_result:ident, $status:expr, $std_result:ident, $duration:expr) => {
        let padding_zeros_string = match $padding_zeros {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $padding_zeros),
        };
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        println!("arguments:");
        println!("{: <35} {:?}", "  └ encrypted string", $clear_s);
        println!("    └ {}", padding_zeros_string);
        println!("results:");
        println!("{: <35} {:?}", "  ├ std result:", $std_result);
        println!("{: <35} {:?}", "  └ FHE result:", $fhe_result);
        if !$status.is_empty() {
            println!("    └ {}", $status);
        }
        println!("time:                               {:?}", $duration);
    };
}

/// Applies the `$method` to both the clear string `$clear_s` and the encrypted
/// string `$encrypted_s`, timing the encrypted process. Then applies a closure
/// to each result in order to obtain two printable objects, then forward
/// everything to the `display` macro.
#[macro_export]
macro_rules! timer {
    ($method:ident, ($clear_s:ident, $padding_zeros:expr, $std_closure:tt), ($encrypted_s:ident, $fhe_closure:tt)) => {
        timer!(
            $method,
            ($clear_s, $padding_zeros, $std_closure),
            ($encrypted_s, $fhe_closure),
            (|_| "")
        )
    };
    ($method:ident, ($clear_s:ident, $padding_zeros:expr, $std_closure:tt), ($encrypted_s:ident, $fhe_closure:tt), $status_closure:tt) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s);
        let duration = start.elapsed();
        let fhe_result = $fhe_closure(&encrypted_fhe_result);
        let std_result = $std_closure($clear_s.$method());
        let status = $status_closure(&encrypted_fhe_result);
        display!(
            $method,
            $clear_s,
            $padding_zeros,
            fhe_result,
            status,
            std_result,
            duration
        )
    };
}

/// Macro for timing a general function. Assumes the result of `SERVER_KEY.$method(&$encrypted_s)` is
/// a `FheString`.
#[macro_export]
macro_rules! time_function {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        time_function!($method, $encrypted_s, $clear_s, 0)
    };
    ($method:ident, $encrypted_s:ident, $clear_s:ident, $padding_zeros:expr) => {
        timer!(
            $method,
            ($clear_s, $padding_zeros, (|clear_result| clear_result)),
            (
                $encrypted_s,
                (|encrypted_result| CLIENT_KEY.decrypt_string(encrypted_result).unwrap())
            )
        );
    };
}

/// Specialized macro for timing `split`-like methods for FheString.
#[macro_export]
macro_rules! time_fhe_split {
    ($method:ident, $return_type:ty, $encrypted_s:ident, $clear_s:ident, $padding_zeros:expr) => {
        timer!(
            $method,
            (
                $clear_s,
                $padding_zeros,
                (|clear_result: $return_type| clear_result
                    .map(|s| String::from(s))
                    .collect::<Vec<_>>())
            ),
            (
                $encrypted_s,
                (|encrypted_result: &FheSplit| {
                    let clear_len = CLIENT_KEY.decrypt_u8(&encrypted_result.number_parts);
                    encrypted_result.parts[..(clear_len as usize)]
                        .iter()
                        .map(|s| CLIENT_KEY.decrypt_string(s).unwrap())
                        .collect::<Vec<String>>()
                })
            )
        );
    };
}

/// Specialized macro for timing the `len` method for FheString.
#[macro_export]
macro_rules! time_len {
    ($encrypted_s:ident, $clear_s:ident) => {
        time_len!($encrypted_s, $clear_s, 0)
    };
    ($encrypted_s:ident, $clear_s:ident, $padding_zeros:expr) => {
        timer!(
            len,
            ($clear_s, $padding_zeros, (|clear_result| clear_result)),
            (
                $encrypted_s,
                (|encrypted_result: &FheStrLength| {
                    match encrypted_result {
                        FheStrLength::Encrypted(encrypted_length) => {
                            CLIENT_KEY.decrypt_u8(&encrypted_length)
                        }
                        FheStrLength::Clear(clear_length) => *clear_length as u8,
                    }
                })
            )
        );
    };
}

/// Specialized macro for timing the `is_empty` method for FheString.
#[macro_export]
macro_rules! time_is_empty {
    ($encrypted_s:ident, $clear_s: ident) => {
        time_is_empty!($encrypted_s, $clear_s, 0)
    };
    ($encrypted_s:ident, $clear_s:ident, $padding_zeros:expr) => {
        timer!(
            is_empty,
            ($clear_s, $padding_zeros, (|clear_result| clear_result)),
            (
                $encrypted_s,
                (|encrypted_result: &FheBool| {
                    match encrypted_result {
                        FheBool::Encrypted(encrypted_bool) => {
                            CLIENT_KEY.decrypt_u8(&encrypted_bool) != 0
                        }
                        FheBool::Clear(clear_bool) => *clear_bool,
                    }
                })
            ),
            (|encrypted_result: &FheBool| {
                match encrypted_result {
                    FheBool::Encrypted(_) => "encrypted",
                    FheBool::Clear(_) => "clear",
                }
            })
        );
    };
}
