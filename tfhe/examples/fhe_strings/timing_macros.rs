#[macro_export]
macro_rules! display_result {
    ($method: ident, $clear_s: expr,$fhe_result: ident, $std_result: ident, $duration: expr) => {
        display_result!($method, $clear_s, $fhe_result, $std_result, $duration, 0)
    };
    ($method: ident, $clear_s: expr, $fhe_result: ident, $std_result: ident, $duration: expr,  $padding_zeros: expr) => {
        display_result!(
            "",
            $method,
            $clear_s,
            $fhe_result,
            $std_result,
            $duration,
            $padding_zeros
        )
    };
    ($status:expr, $method: ident, $clear_s: expr, $fhe_result: ident, $std_result: ident, $duration: expr,  $padding_zeros: expr) => {
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

#[macro_export]
macro_rules! time_function {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        time_function!($method, $encrypted_s, $clear_s, 0)
    };
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s);
        let fhe_result = CLIENT_KEY.decrypt_string(&encrypted_fhe_result).unwrap();
        let duration = start.elapsed();
        let std_result = $clear_s.$method();
        display_result!(
            $method,
            $clear_s,
            fhe_result,
            std_result,
            duration,
            $padding_zeros
        )
    };
}

#[macro_export]
macro_rules! display_result_string_pattern {
    // clear string pattern
    ($method: ident, $clear_s: expr, $clear_pattern: expr, $fhe_result: expr, $std_result: expr, $duration: expr, $string_padding: expr) => {
        let string_padding_zeros_string = match $string_padding {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $string_padding),
        };
        let std_result_string = match $std_result {
            Some(result_string) => format!("Some({:?})", result_string),
            None => "None".to_string(),
        };
        let fhe_result_string = match $fhe_result {
            (1, result_string) => format!("Some({:?})", result_string),
            _ => "None".to_string(),
        };
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        println!("arguments:");
        println!("{: <35} {:?}", "  └ encrypted string", $clear_s);
        println!("    └ {}", string_padding_zeros_string);
        println!("{: <35} {:?}", "  └ clear string pattern", $clear_pattern);
        println!("results:");
        println!("{: <35} {:}", "  ├ std result:", std_result_string);
        println!("{: <35} {:}", "  └ FHE result:", fhe_result_string);
        // if !$status.is_empty() {
        //     println!("    └ {}", $status);
        // }
        println!("time:                               {:?}", $duration);
    };
    ($method: ident, $clear_s: expr, $clear_pattern: expr, $fhe_result: expr, $std_result: expr, $duration: expr, $string_padding: expr, $pattern_padding: expr) => {
        let string_padding_zeros_string = match $string_padding {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $string_padding),
        };
        let pattern_padding_zeros_string = match $string_padding {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $pattern_padding),
        };
        let std_result_string = match $std_result {
            Some(result_string) => format!("Some({:?})", result_string),
            None => "None".to_string(),
        };
        let fhe_result_string = match $fhe_result {
            (1, result_string) => format!("Some({:?})", result_string),
            _ => "None".to_string(),
        };
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        println!("arguments:");
        println!("{: <35} {:?}", "  └ encrypted string", $clear_s);
        println!("    └ {}", string_padding_zeros_string);
        println!(
            "{: <35} {:?}",
            "  └ encrypted string pattern", $clear_pattern
        );
        println!("    └ {}", pattern_padding_zeros_string);
        println!("results:");
        println!("{: <35} {:}", "  ├ std result:", std_result_string);
        println!("{: <35} {:}", "  └ FHE result:", fhe_result_string);
        // if !$status.is_empty() {
        //     println!("    └ {}", $status);
        // }
        println!("time:                               {:?}", $duration);
    };
}

#[macro_export]
macro_rules! std_resultstring_from_type {
    (FheString, $std_result: expr) => {
        "test_std".to_string()
    };
    ((RadixCiphertext, FheString), $std_result: expr) => {
        match $std_result {
            Some(result_string) => format!("Some({:?})", result_string),
            None => "None".to_string(),
        };
    };
}

#[macro_export]
macro_rules! fhe_resultstring_from_type {
    (FheString, $fhe_result: expr) => {
        "test_fhe".to_string()
    };
    ((RadixCiphertext, FheString), $fhe_result: expr) => {
        match $fhe_result {
            (1, result_string) => format!("Some({:?})", result_string),
            _ => "None".to_string(),
        };
    };
}

#[macro_export]
macro_rules! display_result_string_pattern_return_type {
    // clear string pattern
    ($method: ident, $return_type: ident, $clear_s: expr, $clear_pattern: expr, $fhe_result: expr, $std_result: expr, $duration: expr, $string_padding: expr) => {
        let string_padding_zeros_string = match $string_padding {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $string_padding),
        };
        let std_result_string = std_resultstring_from_type!($return_type, $std_result);
        let fhe_result_string = fhe_resultstring_from_type!($return_type, $fhe_result);
        // let std_result_string = match $std_result {
        //     Some(result_string) => format!("Some({:?})", result_string),
        //     None => "None".to_string(),
        // };
        // let fhe_result_string = match $fhe_result {
        //     (1, result_string) => format!("Some({:?})", result_string),
        //     _ => "None".to_string(),
        // };
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        println!("arguments:");
        println!("{: <35} {:?}", "  └ encrypted string", $clear_s);
        println!("    └ {}", string_padding_zeros_string);
        println!("{: <35} {:?}", "  └ clear string pattern", $clear_pattern);
        println!("results:");
        println!("{: <35} {:}", "  ├ std result:", std_result_string);
        println!("{: <35} {:}", "  └ FHE result:", fhe_result_string);
        // if !$status.is_empty() {
        //     println!("    └ {}", $status);
        // }
        println!("time:                               {:?}", $duration);
    };
    ($method: ident, $return_type: ident $clear_s: expr, $clear_pattern: expr, $fhe_result: expr, $std_result: expr, $duration: expr, $string_padding: expr, $pattern_padding: expr) => {
        let string_padding_zeros_string = match $string_padding {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $string_padding),
        };
        let pattern_padding_zeros_string = match $string_padding {
            0 => String::from("no padding"),
            _ => format!("{} padding zeros", $pattern_padding),
        };
        let std_result_string = std_resultstring_from_type!($return_type, $std_result);
        let fhe_result_string = fhe_resultstring_from_type!($return_type, $fhe_result);
        // let std_result_string = match $std_result {
        //     Some(result_string) => format!("Some({:?})", result_string),
        //     None => "None".to_string(),
        // };
        // let fhe_result_string = match $fhe_result {
        //     (1, result_string) => format!("Some({:?})", result_string),
        //     _ => "None".to_string(),
        // };
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        println!("arguments:");
        println!("{: <35} {:?}", "  └ encrypted string", $clear_s);
        println!("    └ {}", string_padding_zeros_string);
        println!(
            "{: <35} {:?}",
            "  └ encrypted string pattern", $clear_pattern
        );
        println!("    └ {}", pattern_padding_zeros_string);
        println!("results:");
        println!("{: <35} {:}", "  ├ std result:", std_result_string);
        println!("{: <35} {:}", "  └ FHE result:", fhe_result_string);
        // if !$status.is_empty() {
        //     println!("    └ {}", $status);
        // }
        println!("time:                               {:?}", $duration);
    };
}

#[macro_export]
macro_rules! time_function_string_pattern_return_type {
    // unpadded string, clear pattern
    ($method: ident, $return_type: ident, $encrypted_s: ident, $clear_s: ident, $clear_pattern: ident) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s, &$clear_pattern);
        let fhe_result = (
            CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.0),
            CLIENT_KEY.decrypt_string(&encrypted_fhe_result.1).unwrap(),
        );
        let duration = start.elapsed();
        let std_result = $clear_s.$method(&$clear_pattern);
        display_result_string_pattern_return_type!(
            $method,
            $return_type,
            $clear_s,
            $clear_pattern,
            fhe_result,
            std_result,
            duration,
            0
        )
    };
    // padded string, clear pattern
    ($method: ident, $return_type: ident, $encrypted_s_padded: ident, $string_padding: expr, $clear_s: ident,  $clear_pattern: ident) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s_padded, &$clear_pattern);
        let fhe_result = (
            CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.0),
            CLIENT_KEY.decrypt_string(&encrypted_fhe_result.1).unwrap(),
        );
        let duration = start.elapsed();
        let std_result = $clear_s.$method(&$clear_pattern);
        display_result_string_pattern_return_type!(
            $method,
            $return_type,
            $clear_s,
            $clear_pattern,
            fhe_result,
            std_result,
            duration,
            $string_padding
        )
    };
    // encrypted string encrypted_pattern
    ($method: ident, $return_type: ident, $encrypted_s: ident, $string_padding: expr, $clear_s: ident,  $clear_pattern:ident, $encrypted_pattern: ident, $pattern_padding: expr) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s, &$encrypted_pattern);
        let fhe_result = (
            CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.0),
            CLIENT_KEY.decrypt_string(&encrypted_fhe_result.1).unwrap(),
        );
        let duration = start.elapsed();
        let std_result = $clear_s.$method(&$clear_pattern);
        display_result_string_pattern_return_type!(
            $method,
            $return_type,
            $clear_s,
            $clear_pattern,
            fhe_result,
            std_result,
            duration,
            $string_padding
        )
    };
}

#[macro_export]
macro_rules! time_function_string_pattern {
    // unpadded string, clear pattern
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $clear_pattern: ident) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s, &$clear_pattern);
        let fhe_result = (
            CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.0),
            CLIENT_KEY.decrypt_string(&encrypted_fhe_result.1).unwrap(),
        );
        let duration = start.elapsed();
        let std_result = $clear_s.$method(&$clear_pattern);
        display_result_string_pattern!(
            $method,
            $clear_s,
            $clear_pattern,
            fhe_result,
            std_result,
            duration,
            0
        )
    };
    // padded string, clear pattern
    ($method: ident, $encrypted_s_padded: ident, $string_padding: expr, $clear_s: ident,  $clear_pattern: ident) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s_padded, &$clear_pattern);
        let fhe_result = (
            CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.0),
            CLIENT_KEY.decrypt_string(&encrypted_fhe_result.1).unwrap(),
        );
        let duration = start.elapsed();
        let std_result = $clear_s.$method(&$clear_pattern);
        display_result_string_pattern!(
            $method,
            $clear_s,
            $clear_pattern,
            fhe_result,
            std_result,
            duration,
            $string_padding
        )
    };
    // encrypted string encrypted_pattern
    ($method: ident, $encrypted_s: ident, $string_padding: expr, $clear_s: ident,  $clear_pattern:ident, $encrypted_pattern: ident, $pattern_padding: expr) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s, &$encrypted_pattern);
        let fhe_result = (
            CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.0),
            CLIENT_KEY.decrypt_string(&encrypted_fhe_result.1).unwrap(),
        );
        let duration = start.elapsed();
        let std_result = $clear_s.$method(&$clear_pattern);
        display_result_string_pattern!(
            $method,
            $clear_s,
            $clear_pattern,
            fhe_result,
            std_result,
            duration,
            $string_padding,
            $pattern_padding
        )
    };
}

#[macro_export]
macro_rules! time_fhe_split {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        time_fhe_split!($method, $encrypted_s, $clear_s, 0)
    };
    ($method: ident, $encrypted_s_padding: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let encrypted_fhe_result = SERVER_KEY.$method(&$encrypted_s_padding);
        let duration = start.elapsed();
        let std_result: Vec<String> = $clear_s.$method().map(|s| String::from(s)).collect();
        let clear_len = CLIENT_KEY.decrypt_integer(&encrypted_fhe_result.number_parts);
        let fhe_result: Vec<String> = encrypted_fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| CLIENT_KEY.decrypt_string(s).unwrap())
            .collect();
        display_result!(
            $method,
            $clear_s,
            fhe_result,
            std_result,
            duration,
            $padding_zeros
        );
    };
}

#[macro_export]
macro_rules! time_len {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        time_len!($method, $encrypted_s, $clear_s, 0)
    };
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let fhe_result = match SERVER_KEY.$method(&$encrypted_s) {
            FheStrLength::Encrypted(encrypted_length) => {
                CLIENT_KEY.decrypt_integer(&encrypted_length)
            }
            FheStrLength::Clear(clear_length) => *clear_length as u32,
        };
        let duration = start.elapsed();
        let std_result = $clear_s.$method();
        display_result!(
            $method,
            $clear_s,
            fhe_result,
            std_result,
            duration,
            $padding_zeros
        );
    };
}

#[macro_export]
macro_rules! time_is_empty {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        time_is_empty!($method, $encrypted_s, $clear_s, 0)
    };
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let (fhe_result, encryption_status) = match &SERVER_KEY.$method(&$encrypted_s) {
            FheBool::Encrypted(encrypted_bool) => (
                CLIENT_KEY.decrypt_integer(&SERVER_KEY.bool_to_radix(encrypted_bool)) != 0,
                "encrypted",
            ),
            FheBool::Clear(clear_bool) => (*clear_bool, "clear"),
        };
        let duration = start.elapsed();
        let std_result = $clear_s.$method();
        display_result!(
            encryption_status,
            $method,
            $clear_s,
            fhe_result,
            std_result,
            duration,
            $padding_zeros
        );
    };
}
