//use crate::ciphertext::FheStrLength;

#[macro_export]
macro_rules! compare_result {
    (RadixCiphertext, $std_result: expr, $fhe_result: expr) => {
        assert_eq!(CLIENT_KEY.decrypt_u8(&$fhe_result), std_result as u8)
    };
    ((RadixCiphertext, RadixCiphertext), $std_result: expr, $fhe_result: expr) => {
        match $std_result {
            Some(n) => {
                assert_eq!(CLIENT_KEY.decrypt_u8(&SERVER_KEY.bool_to_radix(&$fhe_result.0)), 1 as u8);
                assert_eq!(CLIENT_KEY.decrypt_u8(&$fhe_result.1), n as u8);
            }
            None => assert_eq!(CLIENT_KEY.decrypt_u8(&SERVER_KEY.bool_to_radix(&$fhe_result.0)), 0),
        }
    };
    (FheSplit, $std_result: expr, $fhe_result: expr) => {
        let clear_len = CLIENT_KEY.decrypt_u8(&$fhe_result.number_parts);
        let std_split: Vec<String> = $std_result.map(|s| String::from(s)).collect();
        let clear_split: Vec<String> = $fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| CLIENT_KEY.decrypt_string(s).unwrap())
            .collect();
        assert_eq!(clear_split, std_split);

        assert_eq!(clear_len, std_split.len() as u8);
    };
    (FheString, $std_result: expr, $fhe_result: expr) => {
        match $fhe_result.len() {
            FheStrLength::Clear(clear_length) => assert_eq!(*clear_length, $std_result.len()),
            FheStrLength::Encrypted(encrypted_length) => assert_eq!(
                CLIENT_KEY.decrypt_u8(encrypted_length),
                $std_result.len() as u8
            ),
        }
        assert_eq!(
            CLIENT_KEY.decrypt_string(&$fhe_result).unwrap(),
            $std_result
        );
    };
    ((RadixCiphertext, FheString), $std_result: expr, $fhe_result: expr) => {
        match $std_result {
            Some(std_string) => {
                assert_eq!(
                    CLIENT_KEY.decrypt_string(&$fhe_result.1).unwrap(),
                    std_string
                );
                assert_eq!(CLIENT_KEY.decrypt_u8(&SERVER_KEY.bool_to_radix(&$fhe_result.0)), 1);
            }
            _ => {
                assert_eq!(CLIENT_KEY.decrypt_u8(&SERVER_KEY.bool_to_radix(&$fhe_result.0)), 0);
            }
        }
    };
}

#[macro_export]
macro_rules! test_option_index_char_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

           #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
        compare_result!((RadixCiphertext,RadixCiphertext), std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
        compare_result!((RadixCiphertext,RadixCiphertext), std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_encrypted_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
        compare_result!((RadixCiphertext,RadixCiphertext), std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_2_encrypted_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
        compare_result!((RadixCiphertext,RadixCiphertext), std_result, fhe_result);
            }
        }
    };
}

#[macro_export]
macro_rules! test_option_index_string_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
		compare_result!((RadixCiphertext, RadixCiphertext), std_result, fhe_result);

    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
		compare_result!((RadixCiphertext, RadixCiphertext), std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
 		compare_result!((RadixCiphertext, RadixCiphertext), std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!((RadixCiphertext, RadixCiphertext), std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!((RadixCiphertext, RadixCiphertext), std_result, fhe_result);
    	    }
        }
    };
}

#[macro_export]
macro_rules! test_option_string_char_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

           #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
        compare_result!((RadixCiphertext,FheString), std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
        compare_result!((RadixCiphertext,FheString), std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_encrypted_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
        compare_result!((RadixCiphertext,FheString), std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_2_encrypted_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
        compare_result!((RadixCiphertext,FheString), std_result, fhe_result);
            }
        }
    };
}

#[macro_export]
macro_rules! test_option_string_string_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
		compare_result!((RadixCiphertext, FheString), std_result, fhe_result);

    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
		compare_result!((RadixCiphertext, FheString), std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
 		compare_result!((RadixCiphertext, FheString), std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!((RadixCiphertext, FheString), std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!((RadixCiphertext, FheString), std_result, fhe_result);
    	    }
        }
    };
}

#[macro_export]
macro_rules! test_fhe_add_string_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
    		let std_result = String::from($string_arg)+$pattern_arg;
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(encrypted_s, &$pattern_arg);
		compare_result!(FheString, std_result, fhe_result);

    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
    		let std_result = String::from($string_arg)+$pattern_arg;
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(encrypted_s, &$pattern_arg);
		compare_result!(FheString, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    		let std_result = String::from($string_arg)+$pattern_arg;
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(encrypted_s, &encrypted_pattern);
 		compare_result!(FheString, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    		let std_result = String::from($string_arg)+$pattern_arg;
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(encrypted_s, &encrypted_pattern);
		compare_result!(FheString, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		let std_result = String::from($string_arg)+$pattern_arg;
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let fhe_result = SERVER_KEY.$method(encrypted_s, &encrypted_pattern);
		compare_result!(FheString, std_result, fhe_result);
    	    }
        }
    };
}

#[macro_export]
macro_rules! test_fhe_add_char_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_clear_" $pattern_arg>]() {
            let mut std_result = String::from($string_arg);
        std_result.push($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(encrypted_s, &$pattern_arg);
        compare_result!(FheString, std_result, fhe_result);

            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_" $pattern_arg>]() {
        let mut std_result = String::from($string_arg);
        std_result.push($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(encrypted_s, &$pattern_arg);
        compare_result!(FheString, std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_encrypted_" $pattern_arg >]() {
            let mut std_result = String::from($string_arg);
        std_result.push($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
        let fhe_result = SERVER_KEY.$method(encrypted_s, &encrypted_pattern);
         compare_result!(FheString, std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_2_encrypted_" $pattern_arg >]() {
            let mut std_result = String::from($string_arg);
        std_result.push($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
        let fhe_result = SERVER_KEY.$method(encrypted_s, &encrypted_pattern);
        compare_result!(FheString, std_result, fhe_result);
            }
        }
    };
}

#[macro_export]
macro_rules! test_fhe_split_string_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
 		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }
        }
    };
}

#[macro_export]
macro_rules! test_splitn_string_pattern {
    ($method: ident, $integer_arg: expr, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &integer_arg,  &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
	//	let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method( &encrypted_s, &integer_arg, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
	//	let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer,  &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &integer_arg,  &encrypted_pattern);
 		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
	//	let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer,  &encrypted_pattern);
 		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method( &encrypted_s, &integer_arg, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
	//	let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer,  &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &integer_arg,  &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
		let fhe_result = SERVER_KEY.$method( &encrypted_s, &encrypted_integer, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }
        }
    };
}

#[macro_export]
macro_rules! test_splitn_char_pattern {
    ($method: ident, $integer_arg: expr, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &integer_arg, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method( &encrypted_s, &integer_arg, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer, &$pattern_arg);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_0_" $pattern_arg "_encrypted">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
		let fhe_result = SERVER_KEY.$method( &encrypted_s, &integer_arg, &encrypted_pattern);
 		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_0_" $pattern_arg "_encrypted">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer, &encrypted_pattern);
 		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_clear_" $string_arg "_padding_2_" $pattern_arg "_encrypted">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
		let fhe_result = SERVER_KEY.$method( &encrypted_s, &integer_arg, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $integer_arg "_encrypted_" $string_arg "_padding_2_" $pattern_arg "_encrypted">]() {
		let integer_arg : usize = $integer_arg;
    		let std_result = $string_arg.$method($integer_arg, $pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
		let encrypted_integer = CLIENT_KEY.encrypt_u8($integer_arg);
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_integer, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }
        }
    };
}

#[macro_export]
macro_rules! test_fhe_split_char_pattern {
    ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
        paste::item! {

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
        compare_result!(FheSplit, std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
        compare_result!(FheSplit, std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_0_char_" $pattern_arg >]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
            let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
        let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
         compare_result!(FheSplit, std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $string_arg "_padding_2_char_" $pattern_arg >]() {
            let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
        let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
        let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
        compare_result!(FheSplit, std_result, fhe_result);
            }
        }
    };
}

#[macro_export]
macro_rules! test_fhe_split_ascii_whitespace {
    ($method: ident, $string_arg: expr, $num: expr) => {
        paste::item! {
            #[test]
            fn [<"test_" $method "_" $num "_padding_0">]() {
            let std_result = $string_arg.$method();
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s);
        compare_result!(FheSplit, std_result, fhe_result);
            }

            #[test]
            fn [<"test_" $method "_" $num "_random_padding_2">]() {
            let std_result = $string_arg.$method();
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s);
        compare_result!(FheSplit, std_result, fhe_result);
            }
        }
    };
}

#[macro_export]
macro_rules! test_fhe_string_string_pattern {
    ($method: ident, $string_arg: expr, $old_pattern_arg: expr, $new_string_arg: expr) => {
        paste::item! {

    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
            //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, $new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg,2).unwrap();
            //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, $new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_padding_0_encrypted_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str(&$new_string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_encrypted_padding_1_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str_padding(&$new_string_arg,1).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_padding_0_encrypted_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str(&$new_string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_encrypted_padding_1_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str_padding(&$new_string_arg,1).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new);
		compare_result!(FheString, std_result, fhe_result);
    	    }


	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_padding_0_clear_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &$new_string_arg);
		compare_result!(FheString, std_result, fhe_result);
    	    }


	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_padding_0_clear_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &$new_string_arg);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
	    //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &$new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }


	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
            //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &$new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_clear_string_" $old_pattern_arg "_encrypted_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg,2).unwrap();
            //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, $new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }


    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    	    // 	let std_result = $string_arg.$method($pattern_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    	    // 	let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
	    // 	let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
 	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    	    // 	let std_result = $string_arg.$method($pattern_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    	    // 	let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
	    // 	let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    	    // 	let std_result = $string_arg.$method($pattern_arg);
            //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    	    // 	let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
	    // 	let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }
        }
    };
}

#[macro_export]
macro_rules! test_replace_clear_n_string_pattern {
    ($method: ident,  $string_arg: expr, $old_pattern_arg: expr, $new_string_arg: expr, $n_arg: expr) => {
        paste::item! {

    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($n_arg, $old_pattern_arg, $new_string_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
	    //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$n_arg, $old_pattern_arg, $new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($n_arg, $old_pattern_arg, $new_string_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg,2).unwrap();
	    //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$n_arg, $old_pattern_arg, $new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

	    #[test]
    	    fn [<"test_" $method "_" $n_arg "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_padding_0_encrypted_" $new_string_arg>]() {
    		let std_result = $string_arg.$method( $old_pattern_arg, $new_string_arg, $n_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str(&$new_string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new, &$n_arg);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $n_arg  "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_encrypted_padding_1_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg, $n_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str_padding(&$new_string_arg,1).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new, &$n_arg);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $n_arg "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_padding_0_encrypted_" $new_string_arg>]() {
    		let std_result = $string_arg.$method( $old_pattern_arg, $new_string_arg, $n_arg,);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str(&$new_string_arg).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new, &$n_arg,);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    #[test]
    	    fn [<"test_" $method "_" $n_arg "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_encrypted_padding_1_" $new_string_arg>]() {
    		let std_result = $string_arg.$method($old_pattern_arg, $new_string_arg, $n_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
		let encrypted_new = CLIENT_KEY.encrypt_str_padding(&$new_string_arg,1).unwrap();
                let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &encrypted_new, &$n_arg);
		compare_result!(FheString, std_result, fhe_result);
    	    }

	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($n_arg, $old_pattern_arg, $new_string_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
	    //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &$new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }


	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_1_clear_string_" $old_pattern_arg "_clear_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($n_arg, $old_pattern_arg, $new_string_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,1).unwrap();
	    //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, &$new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_clear_string_" $old_pattern_arg "_encrypted_" $new_string_arg>]() {
    	    // 	let std_result = $string_arg.$method($n_arg, $old_pattern_arg, $new_string_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg,2).unwrap();
	    //     let fhe_result = SERVER_KEY.$method(&encrypted_s, &$old_pattern_arg, $new_string_arg);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }


    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    	    // 	let std_result = $string_arg.$method($pattern_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    	    // 	let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
	    // 	let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
 	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    	    // 	let std_result = $string_arg.$method($pattern_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    	    // 	let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
	    // 	let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }

    	    // #[test]
    	    // fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    	    // 	let std_result = $string_arg.$method($pattern_arg);
	    //     let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    	    // 	let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
	    // 	let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
	    // 	compare_result!(FheString, std_result, fhe_result);
    	    // }
        }
    };
}
