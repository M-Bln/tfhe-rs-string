pub enum Encryption {
    Clear,
    Encrypted,
}
pub type Clear = ();
pub type Encrypted = ();

#[macro_export]
macro_rules! print_arg {
    (String, $clear_arg: ident, $encryption: ident, $padding_zeros: expr, $rank: expr) => {
        //	let encryption = $encryption;
        match $encryption {
            Encryption::Clear => {
                let string_title = format!("  └ {:} clear string", $rank);
                println!("{: <35} {:?}", string_title, $clear_arg);
            }
            Encryption::Encrypted => {
                let string_title = format!("  └ {:} encrypted string", $rank);
                println!("{: <35} {:?}", string_title, $clear_arg);
                println!("    └ {}", padding_to_string($padding_zeros));
            }
        }
    };
    (char, $clear_arg: ident, $encryption: ident, $padding_zeros: expr, $rank: expr) => {
        //	let encryption = $encryption;
        match $encryption {
            Encryption::Clear => {
                let pattern_title = format!("  └ {:} clear character pattern", $rank);
                println!("{: <35} {:?}", pattern_title, $clear_arg);
            }
            Encryption::Encrypted => {
                let pattern_title = format!("  └ {:} encrypted character pattern", $rank);
                println!("{: <35} {:?}", pattern_title, $clear_arg);
            }
        }
    };
    (usize, $clear_arg: ident, $encryption: ident, $padding_zeros: expr, $rank: expr) => {
        //	let encryption = $encryption;
        match $encryption {
            Encryption::Clear => {
                let pattern_title = format!("  └ {:} clear integer argument", $rank);
                println!("{: <35} {:?}", pattern_title, $clear_arg);
            }
            Encryption::Encrypted => {
                let pattern_title = format!("  └ {:} encrypted integer argument", $rank);
                println!("{: <35} {:?}", pattern_title, $clear_arg);
            }
        }
    };
}

#[macro_export]
macro_rules! display_arg {
    (String, $clear_arg: ident, Clear, $padding_zeros: expr, $rank: expr) => {
        let string_title = format!("  └ {:} clear string", $rank);
        println!("{: <35} {:?}", string_title, $clear_arg);
    };
    (String, $clear_arg: ident, Encrypted, $padding_zeros: expr, $rank: expr) => {
        let string_title = format!("  └ {:} encrypted string", $rank);
        println!("{: <35} {:?}", string_title, $clear_arg);
        println!("    └ {}", padding_to_string($padding_zeros));
    };
    (char, $clear_arg: ident, Clear, $padding_zeros: expr, $rank: expr) => {
        let pattern_title = format!("  └ {:} clear character pattern", $rank);
        println!("{: <35} {:?}", pattern_title, $clear_arg);
    };
    (char, $clear_arg: ident, Encrypted, $padding_zeros: expr, $rank: expr) => {
        let pattern_title = format!("  └ {:} encrypted character pattern", $rank);
        println!("{: <35} {:?}", pattern_title, $clear_arg);
        //println!("    └ {}", padding_to_string($padding_zeros));
    };
    (usize, $clear_arg: ident, Clear, $padding_zeros: expr, $rank: expr) => {
        let pattern_title = format!("  └ {:} clear integer argument", $rank);
        println!("{: <35} {:?}", pattern_title, $clear_arg);
    };
    (usize, $clear_arg: ident, Encrypted, $padding_zeros: expr, $rank: expr) => {
        let pattern_title = format!("  └ {:} encrypted integer argument", $rank);
        println!("{: <35} {:?}", pattern_title, $clear_arg);
        //println!("    └ {}", padding_to_string($padding_zeros));
    }; /* (char, $clear_arg: ident, $encryption: ident, $padding_zeros: expr, $rank: expr) => {
        *     //	let encryption = $encryption;
        *     match $encryption {
        *         Encryption::Clear => {
        *             let pattern_title = format!("  └ {:} clear character pattern", $rank);
        *             println!("{: <35} {:?}", pattern_title, $clear_arg);
        *         }
        *         Encryption::Encrypted => {
        *             let pattern_title = format!("  └ {:} encrypted character pattern", $rank);
        *             println!("{: <35} {:?}", pattern_title, $clear_arg);
        *         }
        *     }
        * };
        * (usize, $clear_arg: ident, $encryption: ident, $padding_zeros: expr, $rank: expr) => {
        *     //	let encryption = $encryption;
        *     match $encryption {
        *         Encryption::Clear => {
        *             let pattern_title = format!("  └ {:} clear integer argument", $rank);
        *             println!("{: <35} {:?}", pattern_title, $clear_arg);
        *         }
        *         Encryption::Encrypted => {
        *             let pattern_title = format!("  └ {:} encrypted integer argument", $rank);
        *             println!("{: <35} {:?}", pattern_title, $clear_arg);
        *         }
        *     }
        * }; */
}

// pub fn print_string_arg(s: &str, encryption: Encryption, padding_zeros: usize, rank: String) {
//     match encryption {
//         Encryption::Clear => {
//             let string_title = format!("  └ {:} string clear", rank);
//             println!("{: <35} {:?}", string_title, s);
//         }
//         Encryption::Encrypted => {
//             let string_title = format!("  └ {:} string encrypted", rank);
//             println!("{: <35} {:?}", string_title, s);
//             println!("    └ {}", padding_to_string(padding_zeros));
//         }
//     }
// }

// pub fn print_char_arg(c: char, encryption: Encryption, rank: String) {
//     match encryption {
//         Encryption::Clear => {
//             let pattern_title = format!("  └ {:} clear character pattern", rank);
//             println!("{: <35} {:?}", pattern_title, c);
//         }
//         Encryption::Encrypted => {
//             let pattern_title = format!("  └ {:} encrypted character pattern", rank);
//             println!("{: <35} {:?}", pattern_title, c);
//         }
//     }
// }

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
    // ($clear_s1: ident, $clear_s2: ident, $string_std_result: ident, $string_fhe_result: ident,
    // $return_type: ident, String , $padding_s1: expr, $padding_s2: expr, $duration: ident,
    // $encryption: expr) => {     println!("arguments:");
    //     println!("{: <35} {:?}", "  └ first string encrypted", &$clear_s1);
    //     let padding_string = padding_to_string($padding_s1);
    //     println!("    └ {}", padding_string);
    //     print_string_arg($clear_s2, $encryption, $padding_s2, "second".to_string());
    //     //        println!("{: <35} {:?}", "  └ clear string pattern", $clear_pattern);
    //     println!("results:");
    //     println!("{: <35} {:?}", "  ├ std result:", $string_std_result);
    //     println!("{: <35} {:?}", "  └ FHE result:", $string_fhe_result);
    //     // if !$status.is_empty() {
    //     //     println!("    └ {}", $status);
    //     // }
    //     println!("time:                               {:?}", $duration);
    // };

    // ($clear_s1: ident, $clear_pattern: ident, $string_std_result: ident, $string_fhe_result:
    // ident, $return_type: ident, char , $padding_s1: expr, $padding_s2: expr, $duration: ident,
    // $encryption: expr) => {     println!("arguments:");
    //     println!("{: <35} {:?}", "  └ encrypted string", &$clear_s1);
    //     let padding_string = padding_to_string($padding_s1);
    //     println!("    └ {}", padding_string);
    //     print_char_arg($clear_pattern, $encryption, "".to_string());
    //     //        println!("{: <35} {:?}", "  └ clear string pattern", $clear_pattern);
    //     println!("results:");
    //     println!("{: <35} {:?}", "  ├ std result:", $string_std_result);
    //     println!("{: <35} {:?}", "  └ FHE result:", $string_fhe_result);
    //     // if !$status.is_empty() {
    //     //     println!("    └ {}", $status);
    //     // }
    //     println!("time:                               {:?}", $duration);
    // };
    ($clear_s1: ident, $clear_pattern: ident, $string_std_result: ident, $string_fhe_result: ident, $return_type: ident, $arg_type: ident , $padding_s1: expr, $padding_s2: expr, $duration: ident, $encryption: expr) => {
        println!("arguments:");
        println!("{: <35} {:?}", "  └ encrypted string", &$clear_s1);
        let padding_string = padding_to_string($padding_s1);
        println!("    └ {}", padding_string);
        let encryption: Encryption = $encryption;
        print_arg!(
            $arg_type,
            $clear_pattern,
            encryption,
            $padding_s2,
            "".to_string()
        );
        //print_char_arg($clear_pattern, $encryption, "".to_string());
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
macro_rules! display_timing {
    ($clear_s: ident, $padding_s: expr, $displayable_std_result: ident, $displayable_fhe_result: ident, $return_type: ident, $duration: ident,
     $(($arg_type: ident, $clear_arg: ident, $encryption: ident, $arg_padding: expr)),*) => {
	println!("arguments:");
	println!("{: <35} {:?}", "  └ encrypted string", &$clear_s);
//	let number_padding = $padding_s1;
        let padding_string = padding_to_string($padding_s);
        println!("    └ {}", padding_string);

	$(
	   display_arg!($arg_type, $clear_arg, $encryption, $arg_padding, "");
	)*

	println!("results:");
        println!("{: <35} {:?}", "  ├ std result:", $displayable_std_result);
        println!("{: <35} {:?}", "  └ FHE result:", $displayable_fhe_result);
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
    ($fhe_result: ident, FheOptionString) => {{
        if CLIENT_KEY.decrypt_u8(&$fhe_result.0) == 1 {
            Some(CLIENT_KEY.decrypt_string(&$fhe_result.1).unwrap())
        } else {
            None
        }
    }};
    ($fhe_result: ident, FheOptionInt) => {{
        if CLIENT_KEY.decrypt_u8(&$fhe_result.0) == 1 {
            Some(CLIENT_KEY.decrypt_u8(&$fhe_result.1))
        } else {
            None
        }
    }};
    ($fhe_result: ident, FheSplit) => {{
        let clear_len = CLIENT_KEY.decrypt_u8(&$fhe_result.number_parts);
        $fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| CLIENT_KEY.decrypt_string(s).unwrap())
            .collect::<Vec<String>>()
    }};
}

#[macro_export]
macro_rules! to_string_std_result {
    (add, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {{
        let s1 = $clear_s1.clone();
        s1 + $clear_s2
    }};
    (le, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {
        ($clear_s1 <= $clear_s2.to_string())
    };
    (ge, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {
        ($clear_s1 >= $clear_s2.to_string())
    };
    (eq, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {
        ($clear_s1 == $clear_s2.to_string())
    };
    (eq_ignore_case, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {
        $clear_s1.eq_ignore_ascii_case($clear_s2)
    };
    (ne, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {
        ($clear_s1 != $clear_s2.to_string())
    };
    ($method: ident, $clear_s1: ident, $clear_s2: ident, FheSplit, String) => {{
        let std_result = $clear_s1.$method(&$clear_s2);
        std_result.map(|s| String::from(s)).collect::<Vec<String>>()
    }};
    ($method: ident, $clear_s1: ident, $clear_s2: ident, $return_type: ident, String) => {
        $clear_s1.$method(&$clear_s2)
    };
    ($method: ident, $clear_s1: ident, $clear_s2: ident, FheSplit, char) => {{
        let std_result = $clear_s1.$method($clear_s2);
        std_result.map(|s| String::from(s)).collect::<Vec<String>>()
    }};
    ($method: ident, $clear_s1: ident, $clear_s2: ident, $return_type: ident, char) => {
        $clear_s1.$method($clear_s2)
    };
    ($method: ident, $clear_s1: ident, $clear_s2: ident, $return_type: ident, usize) => {
        $clear_s1.$method($clear_s2)
    };
}

#[macro_export]
macro_rules! displayable_std_result {
    ($std_result: ident, FheSplit) => {
        $std_result
            .map(|s| String::from(s))
            .collect::<Vec<String>>()
    };
    ($std_result: ident, $result_type: ident) => {
        $std_result
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
            $pattern_type,
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
macro_rules! ref_or_itself {
    (String, $arg: ident) => {
        &$arg
    };
    ($arg_type: ident, $arg: ident) => {
        $arg
    };
}

#[macro_export]
macro_rules! time_pair_string {
    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident,
     $return_type: ident, $pattern_type: ident) => {
        time_pair_string!(
            $method,
            $clear_s1,
            $encrypted_s1,
            $clear_s2,
            $encrypted_s2,
            $return_type,
            $pattern_type,
            0
        );
    };
    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident,
     $return_type: ident, $pattern_type: ident, $padding_s1: expr ) => {
        let clear_encryption = Encryption::Clear;
        time_pair_string!(
            $method,
            $clear_s1,
            $encrypted_s1,
            $clear_s2,
            $encrypted_s2,
            $return_type,
            $pattern_type,
            $padding_s1,
            0,
            clear_encryption
        );
    };

    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident,
     $return_type: ident, $pattern_type: ident, $padding_s1: expr, $padding_s2: expr) => {
        let encrypted_encryption = Encryption::Encrypted;
        time_pair_string!(
            $method,
            $clear_s1,
            $encrypted_s1,
            $clear_s2,
            $encrypted_s2,
            $return_type,
            $pattern_type,
            $padding_s1,
            $padding_s2,
            encrypted_encryption
        );
    };

    ($method: ident, $clear_s1: ident, $encrypted_s1: ident, $clear_s2: ident, $encrypted_s2: ident,
     $return_type: ident, $pattern_type: ident, $padding_s1: expr, $padding_s2: expr, $encryption: ident) => {
        let encrypted_s1 = ref_or_clone!($method, $encrypted_s1);
        //let mut encrypted_s1 = $encrypted_s1.clone();
        let start = std::time::Instant::now();
        let fhe_result = match $encryption {
            Encryption::Clear => SERVER_KEY.$method(encrypted_s1, &$clear_s2),
            Encryption::Encrypted => SERVER_KEY.$method(encrypted_s1, &$encrypted_s2),
        };
        let duration = start.elapsed();
        let string_fhe_result = to_string_fhe_result!(fhe_result, $return_type);
        let string_std_result =
            to_string_std_result!($method, $clear_s1, $clear_s2, $return_type, $pattern_type);
        println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
        display_result_pair!(
            $clear_s1,
            $clear_s2,
            string_std_result,
            string_fhe_result,
            $return_type,
            $pattern_type,
            $padding_s1,
            $padding_s2,
            duration,
            $encryption
        )
    };
}
#[macro_export]
macro_rules! pick_arg {
    ( $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, Clear, $arg_padding: expr) => {
	&$clear_arg
    };
    ( $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr) => {
	$encrypted_arg
	match $arg_padding {
	    0 => &$encrypted_arg,
	    _ => &$encrypted_arg_padding,
	}
    };
}
#[macro_export]
macro_rules! time_patterns {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_s: expr, $return_type: ident,
     $(( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr)),*  ) => {
	{
	    let encrypted_s = ref_or_clone!($method, $encrypted_s);
	    let start = std::time::Instant::now();
	    let fhe_result = SERVER_KEY.$method(
		encrypted_s,
		$(
		    pick_arg!($clear_arg, $encrypted_arg, $encrypted_arg_padding, $encryption, $arg_padding),
		 )*
	    );
	    let duration = start.elapsed();
	    let string_fhe_result = to_string_fhe_result!(fhe_result, $return_type);
	   // println!("{:?}", string_fhe_result);

	    let std_result = $clear_s.$method(
	    	$(
	    	   ref_or_itself!($arg_type, $clear_arg),
	    	)*
	    );
	    let displayable_std_result = displayable_std_result!(std_result, $return_type);

//    ($clear_s: ident, $displayable_std_result: ident, $displayable_fhe_result: ident, $return_type: ident, $duration: ident,
  //   $(($arg_type: ident, $clear_arg: ident, $encryption: ident, $arg_padding: expr)),*)
	    display_timing!($clear_s, $padding_s, displayable_std_result, string_fhe_result, $return_type, duration,
	    $(($arg_type, $clear_arg, $encryption, $arg_padding)),*);

	   // println!("{:?}", displayable_std_result);
	}
    };
}

#[macro_export]
macro_rules! time_pair_string_all_paddings {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident, $return_type: ident, $padding_zeros: ident) => {
        time_pair_string!(
            // Unpadded string, clear pattern
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            String
        );
        time_pair_string!(
            // Unpadded string, encrypted unpadded pattern
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            String,
            0,
            0
        );
        if $padding_zeros != 0 {
            time_pair_string!(
                // Padded string, clear pattern
                $method,
                $clear_s,
                $encrypted_s_padding,
                $clear_pattern,
                $encrypted_pattern,
                $return_type,
                String,
                $padding_zeros
            );
            time_pair_string!(
                // Padded string, unpadded pattern
                $method,
                $clear_s,
                $encrypted_s_padding,
                $clear_pattern,
                $encrypted_pattern,
                $return_type,
                String,
                $padding_zeros,
                0
            );
            time_pair_string!(
                // Unpadded string, padded pattern
                $method,
                $clear_s,
                $encrypted_s,
                $clear_pattern,
                $encrypted_pattern_padding,
                $return_type,
                String,
                0,
                $padding_zeros
            );
            time_pair_string!(
                // Padded string, padded pattern
                $method,
                $clear_s,
                $encrypted_s_padding,
                $clear_pattern,
                $encrypted_pattern_padding,
                $return_type,
                String,
                $padding_zeros,
                $padding_zeros
            );
        }
    };
}

#[macro_export]
macro_rules! time_char_pattern_all_paddings {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident, $clear_pattern: ident, $encrypted_pattern: ident,  $return_type: ident, $padding_zeros: ident) => {
        time_pair_string!(
            // Unpadded string, clear pattern
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            char
        );
        time_pair_string!(
            // Unpadded string, encrypted unpadded pattern
            $method,
            $clear_s,
            $encrypted_s,
            $clear_pattern,
            $encrypted_pattern,
            $return_type,
            char,
            0,
            0
        );
        if $padding_zeros != 0 {
            time_pair_string!(
                // Padded string, clear pattern
                $method,
                $clear_s,
                $encrypted_s_padding,
                $clear_pattern,
                $encrypted_pattern,
                $return_type,
                char,
                $padding_zeros
            );
            time_pair_string!(
                // Padded string, unpadded pattern
                $method,
                $clear_s,
                $encrypted_s_padding,
                $clear_pattern,
                $encrypted_pattern,
                $return_type,
                char,
                $padding_zeros,
                0
            );
        }
    };
}
