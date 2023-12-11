#[macro_export]
macro_rules! compare_result {
    (RadixCiphertext, $std_result: expr, $fhe_result: expr) => {
        assert_eq!(CLIENT_KEY.decrypt_u8(&$fhe_result), std_result as u8)
    };
    ((RadixCiphertext, RadixCiphertext), $std_result: expr, $fhe_result: expr) => {
        match $std_result {
            Some(n) => {
                assert_eq!(CLIENT_KEY.decrypt_u8(&$fhe_result.0), 1 as u8);
                assert_eq!(CLIENT_KEY.decrypt_u8(&$fhe_result.1), n as u8);
            }
            None => assert_eq!(CLIENT_KEY.decrypt_u8(&$fhe_result.0), 0),
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
                // let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		// match std_result {
    		// 	Some(result) => {
    		// 	    assert_eq!(result as u8, clear_fhe_result);
    		// 	    assert_eq!(clear_found, 1);
    		// 	},
    		// 	None => assert_eq!(clear_found, 0)
    		// }1

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
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
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
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
		compare_result!(FheSplit, std_result, fhe_result);
    	    }

    	    #[test]
    	    fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		let std_result = $string_arg.$method($pattern_arg);
                let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
		let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
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
