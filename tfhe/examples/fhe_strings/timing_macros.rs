#[macro_export]
macro_rules! time_function_no_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
        let clear_result = CLIENT_KEY.decrypt_string(&fhe_result).unwrap();
        let duration = start.elapsed();
        let std_result = $clear_s.$method();
        println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
        println!("Arguments:");
        println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
        println!("  No padding");
        println!("Results:");
        println!("{0: <35} {1:?}", " -std result:", std_result);
        println!("{0: <35} {1:?}", " -FHE result:", clear_result);
        println!("time:{:?} ", duration);
    };
}

#[macro_export]
macro_rules! time_function_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
        let clear_result = CLIENT_KEY.decrypt_string(&fhe_result).unwrap();
        let duration = start.elapsed();
        let std_result = $clear_s.$method();
        println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
        println!("Arguments:");
        println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
        println!("  {0:} padding zeros", $padding_zeros);
        println!("Results:");
        println!("{0: <35} {1:?}", " -std result:", std_result);
        println!("{0: <35} {1:?}", " -FHE result:", clear_result);
        println!("time:{:?} ", duration);
    };
}

#[macro_export]
macro_rules! display_result_no_padding{
    ($method: ident, $clear_s: expr,$fhe_result: ident, $std_result: ident, $duration: expr, FheSplit) => {
	let clear_len = CLIENT_KEY.decrypt_u8(&$fhe_result.number_parts);
	let clear_split: Vec<String> = $fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| CLIENT_KEY.decrypt_string(s).unwrap())
            .collect();
        let std_split: Vec<String> = $std_result.map(|s| String::from(s)).collect();
	println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
        println!("Arguments:");
        println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
        println!("  No padding");
        println!("Results:");
        println!("{0: <35} {1:?}", " -std result:", std_split);
        println!("{0: <35} {1:?}", " -FHE result:", clear_split);
        println!("time:{:?} ", $duration);
    }
}

#[macro_export]
macro_rules! display_result_padding{
    ($method: ident, $clear_s: expr, $fhe_result: ident, $std_result: ident, $duration: expr,  $padding_zeros: expr, FheSplit) => {
	let clear_len = CLIENT_KEY.decrypt_u8(&$fhe_result.number_parts);
	let clear_split: Vec<String> = $fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| CLIENT_KEY.decrypt_string(s).unwrap())
            .collect();
        let std_split: Vec<String> = $std_result.map(|s| String::from(s)).collect();
	println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
        println!("Arguments:");
        println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
        println!("  {0:} padding zeros", $padding_zeros);
        println!("Results:");
        println!("{0: <35} {1:?}", " -std result:", std_split);
        println!("{0: <35} {1:?}", " -FHE result:", clear_split);
        println!("time:{:?} ", $duration);
    }
}

#[macro_export]
macro_rules! time_fhe_split_no_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
	let duration = start.elapsed();
	let std_result = $clear_s.$method();
	display_result_no_padding!($method, $clear_s, fhe_result, std_result, duration, FheSplit);
    };
}

#[macro_export]
macro_rules! time_fhe_split_padding {
    ($method: ident, $encrypted_s_padding: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s_padding);
	let duration = start.elapsed();
	let std_result = $clear_s.$method();
	display_result_padding!($method, $clear_s, fhe_result, std_result, duration, $padding_zeros, FheSplit);
    };
}



#[macro_export]
macro_rules! time_len_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
        match fhe_result {
            FheStrLength::Encrypted(encrypted_length) => {
                let clear_result = CLIENT_KEY.decrypt_u8(&encrypted_length);
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  {0:} padding zeros", $padding_zeros);
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (encrypted):", clear_result);
                println!("time:{:?} ", duration);
            }
            FheStrLength::Clear(clear_length) => {
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  {0:} padding zeros", $padding_zeros);
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (clear):", clear_length);
                println!("time:{:?} ", duration);
            }
        }
    };
}

#[macro_export]
macro_rules! time_len_no_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
        match fhe_result {
            FheStrLength::Encrypted(encrypted_length) => {
                let clear_result = CLIENT_KEY.decrypt_u8(&encrypted_length);
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  No padding");
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!(
                    "{0: <35} {1:?}",
                    " -FHE result (encrypted, but should be clear!):", clear_result
                );
                println!("time:{:?} ", duration);
            }
            FheStrLength::Clear(clear_length) => {
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  No padding");
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (clear):", clear_length);
                println!("time:{:?} ", duration);
            }
        }
    };
}

#[macro_export]
macro_rules! time_is_empty_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident, $padding_zeros: expr) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
        match &fhe_result {
            FheBool::Encrypted(encrypted_bool) => {
                let clear_result = CLIENT_KEY.decrypt_u8(encrypted_bool);
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  {0:} padding zeros", $padding_zeros);
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (encrypted):", (clear_result != 0));
                println!("time:{:?} ", duration);
            }
            FheBool::Clear(clear_bool) => {
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  {0:} padding zeros", $padding_zeros);
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (clear):", *clear_bool);
                println!("time:{:?} ", duration);
            }
        }
    };
}

#[macro_export]
macro_rules! time_is_empty_no_padding {
    ($method: ident, $encrypted_s: ident, $clear_s: ident) => {
        let start = std::time::Instant::now();
        let fhe_result = SERVER_KEY.$method(&$encrypted_s);
        match &fhe_result {
            FheBool::Encrypted(encrypted_bool) => {
                let clear_result = CLIENT_KEY.decrypt_u8(encrypted_bool);
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  No padding");
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (encrypted, but should be clear!):", (clear_result != 0));
                println!("time:{:?} ", duration);
            }
            FheBool::Clear(clear_bool) => {
                let duration = start.elapsed();
                let std_result = $clear_s.$method();
                println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
                println!("Arguments:");
                println!("{0: <35} {1:?}", " -Encrypted string", $clear_s);
                println!("  No padding");
                println!("Results:");
                println!("{0: <35} {1:?}", " -std result:", std_result);
                println!("{0: <35} {1:?}", " -FHE result (clear):", *clear_bool);
                println!("time:{:?} ", duration);
            }
        }
    };
}



