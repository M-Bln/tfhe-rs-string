mod ciphertext;
mod client_key;
mod integer_arg;
mod pattern;
mod server_key;
mod test_generating_macros;
mod timing_macros;

use crate::ciphertext::{gen_keys_test, ClearOrEncrypted, FheStrLength, FheString};
use crate::client_key::StringClientKey;
use crate::server_key::is_empty::FheBool;
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

    apply_time_function_string_pattern_padding_combinations_return_type!(strip_prefix, FheString);
    apply_time_function_string_pattern_padding_combinations_return_type!(strip_suffix, FheString);

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
}
