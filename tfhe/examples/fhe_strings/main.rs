mod ciphertext;
mod client_key;
mod integer_arg;
mod pattern;
mod server_key;
mod test_generating_macros;

use clap::{Parser};
use lazy_static::lazy_static;
use crate::ciphertext::{FheString, gen_keys_test};
use crate::server_key::StringServerKey;
use crate::client_key::StringClientKey;

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
    #[clap(default_value_t=0, short, long)]
    padding_zeros: usize,
}

lazy_static! {
    pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
    pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
    pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
}

fn main() {
    
    let arguments = Arguments::parse();
    let encrypted_s = CLIENT_KEY.encrypt_str(&arguments.input_string).unwrap();
    let mut fhe_result : FheString;
    let mut clear_result: String;
    println!("trim the encrypted string {:?} with no padding", arguments.input_string);
    let start = std::time::Instant::now();
    fhe_result = SERVER_KEY.trim(&encrypted_s);
    clear_result = CLIENT_KEY.decrypt_string(&fhe_result).unwrap();
    println!("fhe result: {:?}", clear_result);
    println!("in: {:?}", start.elapsed());
    println!("std result: {:?}", arguments.input_string.trim());
}
