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
