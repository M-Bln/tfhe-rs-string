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
use crate::server_key::split::FheSplit;
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

    macro_rules! apply_time_function_twice {
        ($method: ident) => {
            time_function!($method, encrypted_s, clear_s);
            time_function!($method, encrypted_s_padding, clear_s, padding_zeros);
        };
    }

    apply_time_function_twice!(trim);
    apply_time_function_twice!(trim_start);
    apply_time_function_twice!(trim_end);
    apply_time_function_twice!(to_lowercase);
    apply_time_function_twice!(to_uppercase);

    time_len!(encrypted_s, clear_s);
    time_len!(encrypted_s_padding, clear_s, padding_zeros);

    time_is_empty!(encrypted_s, clear_s);
    time_is_empty!(encrypted_s_padding, clear_s, padding_zeros);

    time_fhe_split!(
        split_ascii_whitespace,
        std::str::SplitAsciiWhitespace,
        encrypted_s,
        clear_s,
        0
    );
    time_fhe_split!(
        split_ascii_whitespace,
        std::str::SplitAsciiWhitespace,
        encrypted_s_padding,
        clear_s,
        padding_zeros
    );
}
