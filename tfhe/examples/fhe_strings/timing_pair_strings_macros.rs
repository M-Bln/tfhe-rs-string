pub enum Encryption {
    Clear,
    Encrypted,
}

pub fn print_string_arg(s: &str, encryption: Encryption, padding_zeros: usize, rank: String) {
    match encryption {
        Encryption::Clear => {
            println!("{: <35} {:?}", "  └ second string clear", s);
        }
        Encryption::Encrypted => {
            let string_title = format!("  └ {:} string encrypted", rank);
            println!("{: <35} {:?}", string_title, s);
            println!("    └ {}", padding_to_string(padding_zeros));
        }
    }
}

pub fn padding_to_string(padding_zeros: usize) -> String {
    match padding_zeros {
        0 => String::from("no padding"),
        _ => format!("{} padding zeros", padding_zeros),
    }
}

// #[macro_export]
// macro_rules! to_operator {
//     (add) => {+};
//     (le) => {<=};
// }

// #[macro_export]
// macro_rules! print_second_string_arg {
//     ($clear_s2: ident, String) => {
// 	println!("{: <35} {:?}", "  └ second string clear", $clear_pattern);
//     };
//     ($clear_s2: ident, "encrypted", FheString) => {
// 	println!("{: <35} {:?}", "  └ second string encrypted", $clear_pattern);
// 	println!("    └ {}", padding_to_string($padding_zeros));
//     };
// }

#[macro_export]
macro_rules! display_result_pair {
    ($clear_s1: ident, $clear_s2: ident, $string_std_result: ident, $string_fhe_result: ident, $return_type: ident, $padding_s1: expr, $padding_s2: expr, $duration: ident, $encryption: expr) => {
        println!("arguments:");
        println!("{: <35} {:?}", "  └ first string encrypted", &$clear_s1);
        let padding_string = padding_to_string($padding_s1);
        println!("    └ {}", padding_string);
        print_string_arg($clear_s2, $encryption, $padding_s2, "second".to_string());
        //        println!("{: <35} {:?}", "  └ clear string pattern", $clear_pattern);
        println!("results:");
        println!("{: <35} {:?}", "  ├ std result:", $string_std_result);
        println!("{: <35} {:?}", "  └ FHE result:", $string_fhe_result);
        // if !$status.is_empty() {
        //     println!("    └ {}", $status);
        // }
        println!("time:                               {:?}", $duration);
    };
}

#[macro_export]
macro_rules! to_string_fhe_result {
    ($fhe_result: ident, FheString) => {
        CLIENT_KEY.decrypt_string(&$fhe_result).unwrap()
    };
    ($fhe_result: ident, Bool) => {
        (CLIENT_KEY.decrypt_u8(&$fhe_result) == 1)
    };
}

#[macro_export]
macro_rules! to_string_std_result {
    (add, $clear_s1: ident, $clear_s2: ident) => {{
        let s1 = $clear_s1.clone();
        s1 + $clear_s2
    }};
    (le, $clear_s1: ident, $clear_s2: ident) => {
        ($clear_s1 <= $clear_s2.to_string())
    };
    (ge, $clear_s1: ident, $clear_s2: ident) => {
        ($clear_s1 >= $clear_s2.to_string())
    };
    (eq, $clear_s1: ident, $clear_s2: ident) => {
        ($clear_s1 == $clear_s2.to_string())
    };
    (eq_ignore_case, $clear_s1: ident, $clear_s2: ident) => {
        $clear_s1.eq_ignore_ascii_case($clear_s2)
    };
    (ne, $clear_s1: ident, $clear_s2: ident) => {
        ($clear_s1 != $clear_s2.to_string())
    };
}

#[macro_export]
macro_rules! time_pair_clear_s2 {
    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $return_type: ident, $padding_s1: expr) => {
        let mut encrypted_s1 = $encrypted_s1.clone();
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(encrypted_s1, &$clear_s2);
        let duration = start.elapsed();
        let string_fhe_result = to_string_fhe_result!(fhe_result, $return_type);
        let string_std_result = to_string_std_result!($method, $clear_s1, $clear_s2);
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        display_result_pair!(
            $clear_s1,
            $clear_s2,
            string_std_result,
            string_fhe_result,
            $return_type,
            $padding_s1,
            0,
            duration,
            Encryption::Clear
        )
    };
}

#[macro_export]
macro_rules! ref_or_clone {
    (add, $encrypted_s1: ident) => {
        $encrypted_s1.clone()
    };
    ($method: expr, $encrypted_s1: ident) => {
        &$encrypted_s1
    };
}

#[macro_export]
macro_rules! time_pair_string {
    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident, $return_type: ident) => {
        time_pair_string!(
            $method,
            $clear_s1,
            $encrypted_s1,
            $clear_s2,
            $encrypted_s2,
            $return_type,
            0
        );
    };
    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident, $return_type: ident, $padding_s1: expr) => {
        let clear_encryption = Encryption::Clear;
        time_pair_string!(
            $method,
            $clear_s1,
            $encrypted_s1,
            $clear_s2,
            $encrypted_s2,
            $return_type,
            $padding_s1,
            0,
            clear_encryption
        );
    };

    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident, $return_type: ident, $padding_s1: expr, $padding_s2: expr) => {
        let encrypted_encryption = Encryption::Encrypted;
        time_pair_string!(
            $method,
            $clear_s1,
            $encrypted_s1,
            $clear_s2,
            $encrypted_s2,
            $return_type,
            $padding_s1,
            $padding_s2,
            encrypted_encryption
        );
    };

    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident, $return_type: ident, $padding_s1: expr, $padding_s2: expr, $encryption: ident) => {
        let encrypted_s1 = ref_or_clone!($method, $encrypted_s1);
        //let mut encrypted_s1 = $encrypted_s1.clone();
        let start = std::time::Instant::now();
        let fhe_result = match $encryption {
            Encryption::Clear => SERVER_KEY.$method(encrypted_s1, &$clear_s2),
            Encryption::Encrypted => SERVER_KEY.$method(encrypted_s1, &$encrypted_s2),
        };
        let duration = start.elapsed();
        let string_fhe_result = to_string_fhe_result!(fhe_result, $return_type);
        let string_std_result = to_string_std_result!($method, $clear_s1, $clear_s2);
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        display_result_pair!(
            $clear_s1,
            $clear_s2,
            string_std_result,
            string_fhe_result,
            $return_type,
            $padding_s1,
            $padding_s2,
            duration,
            $encryption
        )
    };
}

#[macro_export]
macro_rules! time_pair_string_all_paddings {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $clear_pattern: ident, $encrypted_pattern: ident, $return_type: ident, $padding_zeros: ident) => {
        time_pair_string!(
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type
        );
        time_pair_string!(
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            $padding_zeros
        );
        time_pair_string!(
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            $padding_zeros,
            0
        );
        time_pair_string!(
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            0,
            $padding_zeros
        );
        time_pair_string!(
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            $padding_zeros,
            $padding_zeros
        );
    };
}
/* ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident,

* $return_type: ident, $padding_s1: expr, $padding_s2: expr) */
