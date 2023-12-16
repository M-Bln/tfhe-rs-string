/// This file contains macro used to time and compare each function of the FheString API to the
/// standard library. The first part contains general macro to time function with any number of
/// arguments and any types of arguments. The second part contains macro specific to functions
/// taking exaclty two argument such as `add`, `<=` `==`. Some specificity of this case require to
/// use distinct macros. For instance the name differ between the standard library and the FHE
/// version `<=` becomes `le` and so on.

/// Identifier used to pattern match in macro definition.
pub type Clear = ();
pub type Encrypted = ();

/// Macro to display one or two line for each arguments of the function timed.
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
    };
    (usize, $clear_arg: ident, Clear, $padding_zeros: expr, $rank: expr) => {
        let pattern_title = format!("  └ {:} clear integer argument", $rank);
        println!("{: <35} {:?}", pattern_title, $clear_arg);
    };
    (usize, $clear_arg: ident, Encrypted, $padding_zeros: expr, $rank: expr) => {
        let pattern_title = format!("  └ {:} encrypted integer argument", $rank);
        println!("{: <35} {:?}", pattern_title, $clear_arg);
    };
}

pub fn padding_to_string(padding_zeros: usize) -> String {
    match padding_zeros {
        0 => String::from("no padding"),
        _ => format!("{} padding zeros", padding_zeros),
    }
}

/// Macro to display the timing result for any number and types of arguments
#[macro_export]
macro_rules! display_timing {
    ($clear_s: ident, $padding_s: expr, $displayable_std_result: ident, $displayable_fhe_result: ident, $return_type: ident, $duration: ident,
     $(($arg_type: ident, $clear_arg: ident, $encryption: ident, $arg_padding: expr)),*) => {
	println!("arguments:");
	println!("{: <35} {:?}", "  └ encrypted string", &$clear_s);
        let padding_string = padding_to_string($padding_s);
        println!("    └ {}", padding_string);

	$(
	   display_arg!($arg_type, $clear_arg, $encryption, $arg_padding, "");
	)*

	println!("results:");
        println!("{: <35} {:?}", "  ├ std result:", $displayable_std_result);
        println!("{: <35} {:?}", "  └ FHE result:", $displayable_fhe_result);
        println!("time:                               {:?}", $duration);
    };
}

/// Put the result from the FHE function in a pretty form before display
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

/// Put the result from the function of the std library in a pretty form before display
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

/// Macro to add a & when references need to be taken as argument instead of values
#[macro_export]
macro_rules! ref_or_itself {
    (String, $arg: ident) => {
        &$arg
    };
    ($arg_type: ident, $arg: ident) => {
        $arg
    };
}

/// Macro used to generate the list of arguments to FHE methods
#[macro_export]
macro_rules! pick_arg {
    ( $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, Clear, $arg_padding: expr) => {
        &$clear_arg
    };
    ( $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr) => {
        //$encrypted_arg
        match $arg_padding {
            0 => &$encrypted_arg,
            _ => &$encrypted_arg_padding,
        }
    };
}

/// General macro to time method for a specify encryption and padding for each arguments as well as
/// a padding for s. TODO, generate all possible combination and call this macros to generate all
/// timing.
#[macro_export]
macro_rules! time_patterns {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_s: expr, $return_type: ident,
     $(( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr)),*  ) => {
	{
	    let encrypted_s = match $padding_s {
		0 =>  ref_or_clone!($method, $encrypted_s),
		_ =>  ref_or_clone!($method, $encrypted_s_padding),
	    };
	    let start = std::time::Instant::now();
	    let fhe_result = SERVER_KEY.$method(
		encrypted_s,
		$( // Use rep macro to generate the list of argument to the FHE method
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
	    println!("\n\n\n{: <35} {}", "function:", std::stringify!($method));
	    display_timing!($clear_s, $padding_s, displayable_std_result, string_fhe_result, $return_type, duration,
	    $(($arg_type, $clear_arg, $encryption, $arg_padding)),*);

	   // println!("{:?}", displayable_std_result);
	}
    };
}

#[macro_export]
macro_rules! map_push_front {
    ($new_head: expr, $( ($(list_element: expr),*) ),*) => {
	$(
	   ($new_head $(, list_element),*)
	),*
    };
}

// ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_s:
// expr, $return_type: ident,  $(( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident,
// $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr)),*  )

// #[macro_export]
// macro_rules! map_time_patterns {
//     ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  0,
// $return_type: ident, $(($arg_list: expr)),+) => { 	$(
// 	    time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding, 0, $return_type,
// $arg_list); 	)+
//     };
//     ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,
// $padding_zeros: expr, $return_type: ident, $(($arg_list: expr)),+) => { 	$(
// 	    time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding, 0, $return_type,
// $arg_list); 	    time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding,
// $padding_zeros, $return_type, $arg_list); 	)+
//     };
// }

#[macro_export]
macro_rules! map_time_patterns {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  0, $return_type: ident, $(
	( $( ( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr) ),+)
    ),+) => {
	$(
	    time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding, 0, $return_type, $(
		( $arg_type, $clear_arg, $encrypted_arg, $encrypted_arg_padding, $encryption, $arg_padding)
	    ),+ );
	)+
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr, $return_type: ident, $(
	( $( ( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr) ),+)
    ),+) => {
	$(
	    time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding, 0, $return_type, $(
		( $arg_type, $clear_arg, $encrypted_arg, $encrypted_arg_padding, $encryption, $arg_padding)
	    ),+ );
	    time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding, $padding_zeros, $return_type , $(
		( $arg_type, $clear_arg, $encrypted_arg, $encrypted_arg_padding, $encryption, $arg_padding)
	    ),+ );
	)+
    };
}

// ( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident,
// $encryption: ident, $arg_padding: expr)


// #[macro_export]
// macro_rules! all_arguments_from_type {
//     (0, String, $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident) => {
// 	    (String, $clear_arg, $encrypted_arg, $encrypted_arg_padding, Clear, 0),
// 	    (String, $clear_arg, $encrypted_arg, $encrypted_arg_padding, Encrypted, 0)
//     };
//     ($padding_zeros: expr, String, $clear_arg: ident, $encrypted_arg: ident,
// $encrypted_arg_padding: ident) => { 	((String, $clear_arg, $encrypted_arg, $encrypted_arg_padding,
// Clear, 0), 	(String, $clear_arg, $encrypted_arg, $encrypted_arg_padding, Encrypted, 0),
// 	("String", $clear_arg, $encrypted_arg, $encrypted_arg_padding, Encrypted, $padding_zeros))
//     };
//     ($padding_zeros: expr, $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident,
// $encrypted_arg_padding: ident) => { 	($arg_type, $clear_arg, $encrypted_arg,
// $encrypted_arg_padding, Clear, 0), 	($arg_type, $clear_arg, $encrypted_arg,
// $encrypted_arg_padding, Encrypted, 0)     };
// }

// #[macro_export]
// macro_rules! create_arguments_list {
//     (0,  ( String, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident),      $($arg_tuple: expr),+) => {
// 	map_push_front!(( String, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident, Clear, 0), 			create_arguments_list!($padding_zeros,
// $($arg_tuple: expr),+)), 	map_push_front!(( $first_arg_type: ident, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident, Encrypted, 0),
// 			create_arguments_list!($padding_zeros, $($arg_tuple: expr),+))
//     };
//     (0,  ( String, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident)) => { 	(( String, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident, Clear, 0)), 	 (( String,
// $first_clear_arg: ident, $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident,
// Encrypted, 0))     };
//     ($padding_zero: expr,  ( String, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident)) => { 	(( String, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident, Clear, 0)), 	(( String,
// $first_clear_arg: ident, $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident,
// Encrypted, 0)), 	(( String, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident, Encrypted, $paddiing_zeros))     };
//     ($padding_zeros: expr,  ( $first_arg_type: ident, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident),      $($arg_tuple: expr),+) =>
// { 	map_push_front!(( $first_arg_type: ident, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident, Clear, 0), 			create_arguments_list!($padding_zeros,
// $($arg_tuple: expr),+)), 	map_push_front!(( $first_arg_type: ident, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident, Encrypted, 0),
// 			create_arguments_list!($padding_zeros, $($arg_tuple: expr),+))
//     };
//     ($padding_zeros: expr,  ( $first_arg_type: ident, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident)) => { 	(( $first_arg_type:
// ident, $first_clear_arg: ident, $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident,
// Clear, 0)), 	 (( $first_arg_type: ident, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident, Encrypted, 0))     };
//     ($padding_zeros: expr) => {};
// }

// #[macro_export]
// macro_rules!  time_patterns_all_cases {
//     ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,
// $return_type: ident,     $padding_zeros: expr,
//      $($arg_tuple: expr),+) => {
//  	map_time_patterns!($method, $clear_s, $encrypted_s, $encrypted_s_padding, $padding_zeros,
// $return_type ,create_arguments_list!($padding_zeros, $($arg_tuple),+););     };
// }

//

// #[macro_export]
// macro_rules! map_time_patterns_ident {
//     () => {map_time_patterns};
// }

//($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,
//($method: $padding_zeros: expr, $return_type: ident, $($arg_list: expr),+)

// ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_s:
// expr, $return_type: ident,  $(( $arg_type: ident, $clear_arg: ident, $encrypted_arg: ident,
// $encrypted_arg_padding: ident, $encryption: ident, $arg_padding: expr)),*  ) #[macro_export]
// macro_rules! create_arguments_list {
//     ($padding_zeros: expr, ( $first_arg_type: ident, $first_clear_arg: ident,
// $first_encrypted_arg: ident, $first_encrypted_arg_padding: ident),      $(( $arg_type: ident,
// $clear_arg: ident, $encrypted_arg: ident, $encrypted_arg_padding: ident)),+) => {
// 	( $first_arg_type: ident, $first_clear_arg: ident, $first_encrypted_arg: ident,
// $first_encrypted_arg_padding: ident, Clear, 0), 	create_arguments_list!($padding_zeros,
// $padding_zeros, $(($arg_type, $clear_arg, $encrypted_arg, $encrypted_arg_padding)),+ )     };
// }

// #[macro_export]  TODO, Macro to generate all combinations of clear / encryption / padding for all
// arguments by calling time_patterns; macro_rules! time_patterns_all_subcases{
//     ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,
// $padding_zeros: expr, $return_type: ident,      $(( $arg_type: ident, $clear_arg: ident,
// $encrypted_arg: ident, $encrypted_arg_padding: ident)),*  ) => {

//     };
// }

///////////////////////////////////////////////////////////////////////////////////////////

/// Second part, timing macros for functions taking exactly two arguments.

/// Type used to pattern match in the macros, specific to the function taking two arguments.
pub enum Encryption {
    Clear,
    Encrypted,
}

/// Macro to display one or two line for each arguments of the function timed, specific to functions
/// taking two arguments.
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

/// Macro to display the timing result for functions taking exactly two arguments
#[macro_export]
macro_rules! display_result_pair {
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

/// Put the result from the function of the std library in a pretty form before display.
/// This macro is specific to the case of functions taking two arguments, in particular
/// two string arguments such as `==`, `<=` etc. whose  name differ from their FHE variants
/// `eq`, `le` etc.
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

/// Macro to clone the string s instead of reference when necessary (for the `add` function)
#[macro_export]
macro_rules! ref_or_clone {
    (add, $encrypted_s1: ident) => {
        $encrypted_s1.clone()
    };
    ($method: expr, $encrypted_s1: ident) => {
        &$encrypted_s1
    };
}

/// Macro to time functions taking one argument in addition of s1
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



/// Dispatching macro to time all cases of encryption and padding

#[macro_export]
macro_rules! time_splitn_all_cases {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  0,
     ($clear_integer: ident, $encrypted_integer:ident),
     ($arg_type: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            0,
            FheSplit,
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            )
        );
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr,
     ($clear_integer: ident, $encrypted_integer:ident),
     (String, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            0,
            FheSplit,
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            )
        );
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            $padding_zeros,
            FheSplit,
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    $padding_zeros
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    String,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    $padding_zeros
                )
            )
        );
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr,
     ($clear_integer: ident, $encrypted_integer:ident),
     ($arg_type: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            0,
            FheSplit,
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            )
        );
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            $padding_zeros,
            FheSplit,
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Clear,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Clear,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            ),
            (
                (
                    usize,
                    $clear_integer,
                    $encrypted_integer,
                    $encrypted_integer,
                    Encrypted,
                    0
                ),
                (
                    $arg_type,
                    $clear_pattern,
                    $encrypted_pattern,
                    $encrypted_pattern_padding,
                    Encrypted,
                    0
                )
            )
        );
    };
}

#[macro_export]
macro_rules! time_replace_all_cases {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  0,
     ($old_arg_type: ident, $old_clear_pattern: ident, $old_encrypted_pattern: ident, $old_encrypted_pattern_padding: ident),
     ($arg_type: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            0,
            FheString,
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
	    (
		($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)	    
	    )
	    
        );
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr,
     (String, $old_clear_pattern: ident, $old_encrypted_pattern: ident, $old_encrypted_pattern_padding: ident),
     (String, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            $padding_zeros,
            FheString,
            (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
            (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
	    (
		(String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)
	    ),
	    (
		(String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, $padding_zeros)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)	    
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)	    
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, $padding_zeros)	    
	    )	
	    
        );
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr,
     ($old_arg_type: ident, $old_clear_pattern: ident, $old_encrypted_pattern: ident, $old_encrypted_pattern_padding: ident),
     ($arg_type: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            $padding_zeros,
            FheString,
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0)
            ),
	    (
		($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0)	    
	    )
	    
        );
    };
}


#[macro_export]
macro_rules! time_replacen_all_cases {
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  0,
     ($old_arg_type: ident, $old_clear_pattern: ident, $old_encrypted_pattern: ident, $old_encrypted_pattern_padding: ident),
     ($arg_type: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident),
     ($clear_integer: ident, $encrypted_integer:ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            0,
            FheString,
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
	    (
		($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
	    (
		($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    )
	    
        );
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr,
     (String, $old_clear_pattern: ident, $old_encrypted_pattern: ident, $old_encrypted_pattern_padding: ident),
     (String, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident),
     ($clear_integer: ident, $encrypted_integer:ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            $padding_zeros,
            FheString,
            (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
            (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
	    (
		(String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
		(String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, $padding_zeros),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, $padding_zeros),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
            (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
	    (
		(String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    ),
	    (
		(String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, $padding_zeros),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    ),
	    (
                (String, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, $padding_zeros),
                (String, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, $padding_zeros),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    )
        );
    };
    ($method: ident, $clear_s: ident, $encrypted_s: ident, $encrypted_s_padding: ident,  $padding_zeros: expr,
     ($old_arg_type: ident, $old_clear_pattern: ident, $old_encrypted_pattern: ident, $old_encrypted_pattern_padding: ident),
     ($arg_type: ident, $clear_pattern: ident, $encrypted_pattern: ident, $encrypted_pattern_padding: ident),
     ($clear_integer: ident, $encrypted_integer:ident)) => {
        map_time_patterns!(
            $method,
            $clear_s,
            $encrypted_s,
            $encrypted_s_padding,
            $padding_zeros,
            FheString,
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
            ),
	    (
		($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Clear, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
            (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Clear, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
            ),
	    (
		($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Clear, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    ),
	    (
                ($old_arg_type, $old_clear_pattern, $old_encrypted_pattern, $old_encrypted_pattern_padding, Encrypted, 0),
                ($arg_type, $clear_pattern, $encrypted_pattern, $encrypted_pattern_padding, Encrypted, 0),
		(usize, $clear_integer, $encrypted_integer, $encrypted_integer, Encrypted, 0)
	    )
        );
    };
}
