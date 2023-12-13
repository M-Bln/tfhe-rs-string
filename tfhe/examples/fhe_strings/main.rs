mod ciphertext;
mod client_key;
mod integer_arg;
mod pattern;
mod server_key;
mod test_generating_macros;
mod timing_macros;

use crate::ciphertext::{gen_keys_test, FheString};
use crate::client_key::StringClientKey;
use crate::server_key::StringServerKey;
//use crate::{time_function};
use clap::Parser;
use lazy_static::lazy_static;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// Input string to process
    input_string: String,

    /// First string pattern argument
    pattern: String,

    /// First char pattern argument
    #[arg(short, long)]
    char_pattern: Option<char>,

    /// Second pattern argument for replace
    #[arg(short, long)]
    replace_pattern: Option<String>,

    /// Integer argument
    #[arg(short, long)]
    integer_arg: Option<usize>,

    /// Padding
    #[clap(default_value_t = 2, short, long)]
    padding_zeros: usize,
}

lazy_static! {
    pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
    pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
    pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
}

fn main() {
    let arguments = Arguments::parse();
    let clear_s = arguments.input_string;
    let padding_zeros = arguments.padding_zeros;
    let encrypted_s = CLIENT_KEY.encrypt_str(&clear_s).unwrap();
    let encrypted_s_padding = CLIENT_KEY
        .encrypt_str_padding(&clear_s, padding_zeros)
        .unwrap();

    macro_rules! time_function {
        ($method: ident) => {
            time_function_no_padding!($method, encrypted_s, clear_s);
            time_function_padding!($method, encrypted_s_padding, clear_s, padding_zeros);
        };
    }

    time_function!(trim);
    time_function!(trim_start);
    time_function!(trim_end);
    time_function!(to_lowercase);
    time_function!(to_uppercase);

    // let mut fhe_result: FheString;
    // let mut clear_result: String;
    // println!("\n\nfunction: trim");
    // println!("String argument: {:?} (no padding)\n", arguments.input_string);
    // let start = std::time::Instant::now();
    // fhe_result = SERVER_KEY.trim(&encrypted_s);
    // clear_result = CLIENT_KEY.decrypt_string(&fhe_result).unwrap();
    // let duration = start.elapsed();
    // println!("FHE result:");
    // println!("SERVER_KEY.trim(&encrypted_string) = {:?}\n", clear_result);
    // println!("Computed in: {:?}\n", start.elapsed());
    // println!("Rust standard library result:");
    // println!("{:?}.trim() = {:?}\n", arguments.input_string, arguments.input_string.trim());
    // println!(
    //     "{0: <10} | {1: <10} | {2: <10} | {3: <10} ",
    //     "Function", "string argument", "pattern", "second_pattern",
    // );
    // println!("\n\n\nfunction: trim");
    // println!("Arguments:");
    // println!("String argument: \n s = {:?};", arguments.input_string);
    // println!("Encrypted string (no padding) \n &encrypted_s = CLIENT_KEY.encrypt_str({:?})",
    // arguments.input_string); println!("{0: <40} = {1:? }", "str_arg.trim()",
    // arguments.input_string.trim()); println!("{0: <40} = {1:? }",
    // "SERVER_KEY.trim(&encrypted_str)", clear_result); println!("time:{:?} ", duration);

    // println!("\n\n\n{0: <20} {1:}", "function:", "trim");
    // println!("Arguments:");
    // println!("{0: <35} {1:?}", " -Encrypted string (no padding)", arguments.input_string);
    // println!("Results:");
    // println!("{0: <35} {1:?}", " -std result:", arguments.input_string.trim() );
    // println!("{0: <35} {1:?}", " -FHE result:", clear_result );
    // println!("time:{:?} ", duration);

    // #[macro_export]
    // macro_rules! time_function_no_padding{
    // 	($method: ident) => {
    // 	    let start = std::time::Instant::now();
    // 	    let fhe_result = SERVER_KEY.$method(&encrypted_s);
    // 	    let clear_result = CLIENT_KEY.decrypt_string(&fhe_result).unwrap();
    // 	    let duration = start.elapsed();
    // 	    let std_result = clear_s.$method();
    // 	    println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
    // 	    println!("Arguments:");
    // 	    println!("{0: <35} {1:?}", " -Encrypted string", clear_s);
    // 	    println!("  No padding");
    // 	    println!("Results:");
    // 	    println!("{0: <35} {1:?}", " -std result:", std_result);
    // 	    println!("{0: <35} {1:?}", " -FHE result:", clear_result);
    // 	    println!("time:{:?} ", duration);
    // 	}
    // };

    // #[macro_export]
    // macro_rules! time_function_padding{
    // 	($method: ident) => {
    // 	    let start = std::time::Instant::now();
    // 	    let fhe_result = SERVER_KEY.$method(&encrypted_s_padding);
    // 	    let clear_result = CLIENT_KEY.decrypt_string(&fhe_result).unwrap();
    // 	    let duration = start.elapsed();
    // 	    let std_result = clear_s.$method();
    // 	    println!("\n\n\n{0: <20} {1:}", "function:", std::stringify!($method));
    // 	    println!("Arguments:");
    // 	    println!("{0: <35} {1:?}", " -Encrypted string", clear_s);
    // 	    println!("  {0:} padding zeros", padding_zeros);
    // 	    println!("Results:");
    // 	    println!("{0: <35} {1:?}", " -std result:", std_result);
    // 	    println!("{0: <35} {1:?}", " -FHE result:", clear_result);
    // 	    println!("time:{:?} ", duration);
    // 	}
    // };

    // #[macro_export]
    // macro_rules! time_function{
    // 	($method: ident) => {
    // 	    time_function_no_padding!($method);
    // 	    time_function_padding!($method);
    // 	}
    // };
}
