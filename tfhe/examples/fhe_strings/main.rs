mod ciphertext;
mod client_key;
mod integer_arg;
mod pattern;
mod server_key;
mod test_generating_macros;
mod timing_macros;
mod timing_pair_strings_macros;

use crate::ciphertext::{gen_keys_test, ClearOrEncrypted, FheStrLength, FheString};
use crate::client_key::StringClientKey;
use crate::server_key::StringServerKey;
//use crate::integer_arg::FheIntegerArg;
use tfhe::integer::RadixCiphertext;
//use crate::{time_function};
use clap::Parser;
use lazy_static::lazy_static;
use timing_pair_strings_macros::{padding_to_string, print_string_arg, Encryption};

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
    #[clap(default_value_t = 5, short, long)]
    max_number_repeatition: usize,

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
    let clear_pattern = arguments.pattern.as_str();
    let padding_zeros = arguments.padding_zeros;

    let encrypted_s = CLIENT_KEY.encrypt_str(&clear_s).unwrap();
    let encrypted_s_padding = CLIENT_KEY
        .encrypt_str_padding(&clear_s, padding_zeros)
        .unwrap();

    let encrypted_pattern = CLIENT_KEY.encrypt_str(&clear_pattern).unwrap();
    let encrypted_pattern_padded = CLIENT_KEY
        .encrypt_str_padding(&clear_pattern, padding_zeros)
        .unwrap();

    macro_rules! apply_time_function_twice {
        ($method: ident) => {
            time_function!($method, encrypted_s, clear_s);
            time_function!($method, encrypted_s_padding, clear_s, padding_zeros);
        };
    }

    macro_rules! apply_time_function_string_pattern_padding_combinations {
        ($method: ident) => {
            time_function_string_pattern!($method, encrypted_s, clear_s, clear_pattern);
            time_function_string_pattern!(
                $method,
                encrypted_s_padding,
                padding_zeros,
                clear_s,
                clear_pattern
            );
            time_function_string_pattern!(
                $method,
                encrypted_s,
                0,
                clear_s,
                clear_pattern,
                encrypted_pattern,
                0
            );
            time_function_string_pattern!(
                $method,
                encrypted_s_padding,
                padding_zeros,
                clear_s,
                clear_pattern,
                encrypted_pattern,
                0
            );
            time_function_string_pattern!(
                $method,
                encrypted_s,
                0,
                clear_s,
                clear_pattern,
                encrypted_pattern_padded,
                padding_zeros
            );
            time_function_string_pattern!(
                $method,
                encrypted_s_padding,
                padding_zeros,
                clear_s,
                clear_pattern,
                encrypted_pattern_padded,
                padding_zeros
            );
            // encrypted_pattern_padded, clear_pattern, padding_zeros);
            // time_function_string_pattern!($method, encrypted_s_padding, clear_s,
            // encrypted_pattern_padded, clear_pattern, padding_zeros, padding_zeros);
        };
    }

    macro_rules! apply_time_function_string_pattern_padding_combinations_return_type {
        ($method: ident, $return_type: ident) => {
            time_function_string_pattern_return_type!(
                $method,
                $return_type,
                encrypted_s,
                clear_s,
                clear_pattern
            );
            time_function_string_pattern_return_type!(
                $method,
                $return_type,
                encrypted_s_padding,
                padding_zeros,
                clear_s,
                clear_pattern
            );
            time_function_string_pattern_return_type!(
                $method,
                $return_type,
                encrypted_s,
                0,
                clear_s,
                clear_pattern,
                encrypted_pattern,
                0
            );
            time_function_string_pattern_return_type!(
                $method,
                $return_type,
                encrypted_s_padding,
                padding_zeros,
                clear_s,
                clear_pattern,
                encrypted_pattern,
                0
            );
            time_function_string_pattern_return_type!(
                $method,
                $return_type,
                encrypted_s,
                0,
                clear_s,
                clear_pattern,
                encrypted_pattern_padded,
                padding_zeros
            );
            time_function_string_pattern_return_type!(
                $method,
                $return_type,
                encrypted_s_padding,
                padding_zeros,
                clear_s,
                clear_pattern,
                encrypted_pattern_padded,
                padding_zeros
            );
            // encrypted_pattern_padded, clear_pattern, padding_zeros);
            // time_function_string_pattern!($method, encrypted_s_padding, clear_s,
            // encrypted_pattern_padded, clear_pattern, padding_zeros, padding_zeros);
        };
    }

    // apply_time_function_string_pattern_padding_combinations_return_type!(
    //     strip_prefix,
    //     (RadixCiphertext, FheString)
    // );
    // apply_time_function_string_pattern_padding_combinations_return_type!(
    //     strip_suffix,
    //     (RadixCiphertext, FheString)
    // );

    // apply_time_function_twice!(trim);
    // apply_time_function_twice!(trim_start);
    // apply_time_function_twice!(trim_end);
    // apply_time_function_twice!(to_lowercase);
    // apply_time_function_twice!(to_uppercase);

    // time_len!(len, encrypted_s, clear_s);
    // time_len!(len, encrypted_s_padding, clear_s, padding_zeros);

    // time_is_empty!(is_empty, encrypted_s, clear_s);
    // time_is_empty!(is_empty, encrypted_s_padding, clear_s, padding_zeros);

    // time_fhe_split!(split_ascii_whitespace, encrypted_s, clear_s);
    // time_fhe_split!(
    //     split_ascii_whitespace,
    //     encrypted_s_padding,
    //     clear_s,
    //     padding_zeros
    // );

    time_pair_string!(
        add,
        clear_s,
        encrypted_s,
        clear_pattern,
        encrypted_pattern,
        FheString
    );
    time_pair_string!(
        add,
        clear_s,
        encrypted_s,
        clear_pattern,
        encrypted_pattern,
        FheString
    );

    match arguments.integer_arg {
        Some(clear_integer_arg) => {
            time_repeat_clear(&clear_s, &encrypted_s, clear_integer_arg, 0);
            time_repeat_clear(
                &clear_s,
                &encrypted_s_padding,
                clear_integer_arg,
                padding_zeros,
            );

            let encrypted_integer_arg = CLIENT_KEY.encrypt_u8(clear_integer_arg as u8);

            time_repeat_encrypted(
                &clear_s,
                &encrypted_s,
                clear_integer_arg,
                arguments.max_number_repeatition,
                &encrypted_integer_arg,
                0,
            );
            time_repeat_encrypted(
                &clear_s,
                &encrypted_s_padding,
                clear_integer_arg,
                arguments.max_number_repeatition,
                &encrypted_integer_arg,
                padding_zeros,
            );
        }
        _ => (),
    }
}

fn time_repeat_clear(clear_s: &str, encrypted_s: &FheString, clear_n: usize, padding_zeros: usize) {
    let start = std::time::Instant::now();
    let result = SERVER_KEY.repeat_clear(encrypted_s, clear_n);
    let duration = start.elapsed();

    let string_padding_zeros_string = match padding_zeros {
        0 => String::from("no padding"),
        _ => format!("{} padding zeros", padding_zeros),
    };

    println!("\n\n\n{: <35} {}", "function:", std::stringify!(repeat));
    println!("arguments:");
    println!("{: <35} {:?}", "  └ encrypted string", clear_s);
    println!("    └ {}", string_padding_zeros_string);
    println!("{: <35} {:?}", "  └ clear integer", clear_n);
    println!("results:");
    println!("{: <35} {:}", "  ├ std result:", clear_s.repeat(clear_n));
    println!(
        "{: <35} {:}",
        "  └ FHE result:",
        CLIENT_KEY.decrypt_string(&result).unwrap()
    );
    // if !$status.is_empty() {
    //     println!("    └ {}", $status);
    // }
    println!("time:                               {:?}", duration);
}

fn time_repeat_encrypted(
    clear_s: &str,
    encrypted_s: &FheString,
    clear_n: usize,
    max_n: usize,
    encrypted_n: &RadixCiphertext,
    padding_zeros: usize,
) {
    let start = std::time::Instant::now();
    let result = SERVER_KEY.repeat_encrypted(encrypted_s, encrypted_n, max_n);
    let duration = start.elapsed();

    let string_padding_zeros_string = match padding_zeros {
        0 => String::from("no padding"),
        _ => format!("{} padding zeros", padding_zeros),
    };

    println!("\n\n\n{: <35} {}", "function:", std::stringify!(repeat));
    println!("arguments:");
    println!("{: <35} {:?}", "  └ encrypted string", clear_s);
    println!("    └ {}", string_padding_zeros_string);
    println!("{: <35} {:?}", "  └ encrypted integer", clear_n);
    println!("results:");
    println!("{: <35} {:}", "  ├ std result:", clear_s.repeat(clear_n));
    println!(
        "{: <35} {:}",
        "  └ FHE result:",
        CLIENT_KEY.decrypt_string(&result).unwrap()
    );
    // if !$status.is_empty() {
    //     println!("    └ {}", $status);
    // }
    println!("time:                               {:?}", duration);
}
