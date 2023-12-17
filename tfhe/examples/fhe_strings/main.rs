mod ciphertext;
mod client_key;
mod integer_arg;
mod pattern;
mod server_key;
mod test_generating_macros;
mod timing_macros;
mod timing_pair_strings_macros;

use crate::ciphertext::{gen_keys, gen_keys_test, FheStrLength, FheString};
use crate::client_key::StringClientKey;
use crate::server_key::StringServerKey;
//use crate::integer_arg::FheIntegerArg;
use tfhe::integer::RadixCiphertext;
//use crate::{time_function};
use crate::server_key::is_empty::FheBool;
//use crate::server_key::strip::FheOptionString;
use clap::Parser;
use lazy_static::lazy_static;
use timing_pair_strings_macros::{padding_to_string, Encryption};

#[derive(Parser, Debug)]
#[command(about, long_about, verbatim_doc_comment)]
/// Program to time FHE functions acting on encrypted strings and compare the result with the
/// standard library.
///
/// - It takes at least two string arguments, and `input_string` and a string `pattern`.
///
/// - Provide an additional character argument with flag -c to time methods that also accept char.
///
/// - Provide an integer argument with flag -i to time `splitn`, `repeat` etc.
///
/// - Provide a string 'replace_pattenr' with the flag -r to time `replace` and `replacen`.
///
/// - Provide an integer arg with the flag -p to indicate the number of padding zeros to add to
///   string arguments.
struct Arguments {
    /// Input string to process, the program times FHE functions acting on it and compare the
    /// result with the standard library.
    input_string: String,

    /// First pattern argument (string), calls `input_string.method(pattern)`, and the FHE
    /// equivalent for various methods.
    pattern: String,

    /// Optional pattern argument (char),  an additional character argument to time methods that
    /// also accept character patterns.
    #[arg(short, long)]
    char_pattern: Option<char>,

    /// 'Replace by' argument (string), for replace and replacen.
    #[arg(short, long)]
    replace_pattern: Option<String>,

    /// Integer argument, for repeat, splitn, rsplitn and replacen.
    #[arg(short, long)]
    integer_arg: Option<usize>,

    /// Maximum number of repeatition when calling repeat with an encrypted integer arg.
    #[clap(default_value_t = 5, short, long)]
    max_number_repeatition: usize,

    /// Number of padding zeros for string arguments
    #[clap(default_value_t = 0, short, long)]
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

    /// Macro to time function taking one string arguments without and with padding if necessary.
    macro_rules! apply_time_function_twice {
        ($method: ident) => {
            time_function!($method, encrypted_s, clear_s);
            if padding_zeros != 0 {
                time_function!($method, encrypted_s_padding, clear_s, padding_zeros);
            }
        };
    }

    // Times functions taking one string argument without and with padding if necessary.
    apply_time_function_twice!(trim);
    apply_time_function_twice!(trim_start);
    apply_time_function_twice!(trim_end);
    apply_time_function_twice!(to_lowercase);
    apply_time_function_twice!(to_uppercase);

    // Uses specific macros to time functions len, is_empty and split_ascii_withespace
    time_len!(len, encrypted_s, clear_s);
    time_is_empty!(is_empty, encrypted_s, clear_s);
    time_fhe_split!(split_ascii_whitespace, encrypted_s, clear_s);

    if padding_zeros != 0 {
        time_len!(len, encrypted_s_padding, clear_s, padding_zeros);
        time_is_empty!(is_empty, encrypted_s_padding, clear_s, padding_zeros);
        time_fhe_split!(
            split_ascii_whitespace,
            encrypted_s_padding,
            clear_s,
            padding_zeros
        );
    }

    /// Macro to time functions taking two string arguments.  Shorthand to avoid repetition of
    /// written arguments.
    macro_rules! time_pairs {
        ($method: ident, $return_type: ident) => {
            time_pair_string_all_paddings!(
                $method,
                clear_s,
                encrypted_s,
                encrypted_s_padding,
                clear_pattern,
                encrypted_pattern,
                encrypted_pattern_padded,
                $return_type,
                padding_zeros
            );
        };
    }

    // Times functions taking a string and a string pattern argument.
    time_pairs!(add, FheString);

    time_pairs!(eq, Bool);
    time_pairs!(eq_ignore_case, Bool);
    time_pairs!(ne, Bool);
    time_pairs!(le, Bool);
    time_pairs!(ge, Bool);

    time_pairs!(starts_with, Bool);
    time_pairs!(ends_with, Bool);
    time_pairs!(contains, Bool);

    time_pairs!(strip_prefix, FheOptionString);
    time_pairs!(strip_suffix, FheOptionString);

    time_pairs!(find, FheOptionInt);
    time_pairs!(rfind, FheOptionInt);

    time_pairs!(split, FheSplit);
    time_pairs!(split_inclusive, FheSplit);
    time_pairs!(split_terminator, FheSplit);
    time_pairs!(rsplit, FheSplit);
    time_pairs!(rsplit_terminator, FheSplit);

    match arguments.char_pattern {
        Some(clear_char_pattern) => {
            let encrypted_char_pattern = CLIENT_KEY.encrypt_ascii_char(clear_char_pattern as u8);

            /// Macro to time functions taking a string and a character pattern.  Shorthand to avoid
            /// repetition of written arguments.
            macro_rules! time_char_pattern {
                ($method: ident, $return_type: ident) => {
                    time_char_pattern_all_paddings!(
                        $method,
                        clear_s,
                        encrypted_s,
                        encrypted_s_padding,
                        clear_char_pattern,
                        encrypted_char_pattern,
                        $return_type,
                        padding_zeros
                    );
                };
            }

            time_char_pattern!(starts_with, Bool);
            time_char_pattern!(ends_with, Bool);
            time_char_pattern!(contains, Bool);

            time_char_pattern!(find, FheOptionInt);
            time_char_pattern!(rfind, FheOptionInt);

            time_char_pattern!(strip_prefix, FheOptionString);
            time_char_pattern!(strip_suffix, FheOptionString);

            time_char_pattern!(split, FheSplit);
            time_char_pattern!(split_inclusive, FheSplit);
            time_char_pattern!(split_terminator, FheSplit);
            time_char_pattern!(rsplit, FheSplit);
            time_char_pattern!(rsplit_terminator, FheSplit);
        }
        None => (),
    }

    // Times functions taking a string and an integer argument if provided by command line
    // interface.
    match arguments.integer_arg {
        Some(clear_integer_arg) => {
            // let clear_integer_arg = integer_arg as u32;
            let encrypted_integer_arg = CLIENT_KEY.encrypt_integer(clear_integer_arg as u8);

            if padding_zeros != 0 {
                // Branching allow the macros to correctly match literal 0 for padding_zeros, TODO:
                // avoid this branching?
                time_splitn_all_cases!(
                    splitn,
                    clear_s,
                    encrypted_s,
                    encrypted_s_padding,
                    padding_zeros,
                    (clear_integer_arg, encrypted_integer_arg),
                    (
                        String,
                        clear_pattern,
                        encrypted_pattern,
                        encrypted_pattern_padded
                    )
                );
                time_splitn_all_cases!(
                    rsplitn,
                    clear_s,
                    encrypted_s,
                    encrypted_s_padding,
                    padding_zeros,
                    (clear_integer_arg, encrypted_integer_arg),
                    (
                        String,
                        clear_pattern,
                        encrypted_pattern,
                        encrypted_pattern_padded
                    )
                );
            } else {
                time_splitn_all_cases!(
                    splitn,
                    clear_s,
                    encrypted_s,
                    encrypted_s_padding,
                    0,
                    (clear_integer_arg, encrypted_integer_arg),
                    (
                        String,
                        clear_pattern,
                        encrypted_pattern,
                        encrypted_pattern_padded
                    )
                );
                time_splitn_all_cases!(
                    rsplitn,
                    clear_s,
                    encrypted_s,
                    encrypted_s_padding,
                    0,
                    (clear_integer_arg, encrypted_integer_arg),
                    (
                        String,
                        clear_pattern,
                        encrypted_pattern,
                        encrypted_pattern_padded
                    )
                );
            }

            if padding_zeros != 0 {
                time_repeat_encrypted(
                    &clear_s,
                    &encrypted_s_padding,
                    clear_integer_arg,
                    arguments.max_number_repeatition,
                    &encrypted_integer_arg,
                    padding_zeros,
                );
                time_repeat_clear(
                    &clear_s,
                    &encrypted_s_padding,
                    clear_integer_arg,
                    padding_zeros,
                );
            } else {
                time_repeat_clear(&clear_s, &encrypted_s, clear_integer_arg, 0);
                time_repeat_encrypted(
                    &clear_s,
                    &encrypted_s,
                    clear_integer_arg,
                    arguments.max_number_repeatition,
                    &encrypted_integer_arg,
                    0,
                );
            }

            // Time replacen if both the integer argument and the replace pattern are provided by
            // CLI
            match &arguments.replace_pattern {
                Some(replace_pattern) => {
                    let clear_replace_pattern = replace_pattern.as_str();
                    let encrypted_replace_pattern =
                        CLIENT_KEY.encrypt_str(clear_replace_pattern).unwrap();
                    let encrypted_replace_pattern_padding = CLIENT_KEY
                        .encrypt_str_padding(clear_replace_pattern, padding_zeros)
                        .unwrap();
                    if padding_zeros != 0 {
                        time_replacen_all_cases!(
                            replacen,
                            clear_s,
                            encrypted_s,
                            encrypted_s_padding,
                            padding_zeros,
                            (
                                String,
                                clear_pattern,
                                encrypted_pattern,
                                encrypted_pattern_padded
                            ),
                            (
                                String,
                                clear_replace_pattern,
                                encrypted_replace_pattern,
                                encrypted_replace_pattern_padding
                            ),
                            (clear_integer_arg, encrypted_integer_arg)
                        );
                    } else {
                        time_replacen_all_cases!(
                            replacen,
                            clear_s,
                            encrypted_s,
                            encrypted_s_padding,
                            0,
                            (
                                String,
                                clear_pattern,
                                encrypted_pattern,
                                encrypted_pattern_padded
                            ),
                            (
                                String,
                                clear_replace_pattern,
                                encrypted_replace_pattern,
                                encrypted_replace_pattern_padding
                            ),
                            (clear_integer_arg, encrypted_integer_arg)
                        );
                    }
                }
                _ => (),
            }
        }
        _ => (),
    }

    // Times replace if replace_pattern provided by command line interface.
    match arguments.replace_pattern {
        Some(replace_pattern) => {
            let clear_replace_pattern = replace_pattern.as_str();
            let encrypted_replace_pattern = CLIENT_KEY.encrypt_str(clear_replace_pattern).unwrap();
            let encrypted_replace_pattern_padding = CLIENT_KEY
                .encrypt_str_padding(clear_replace_pattern, padding_zeros)
                .unwrap();
            if padding_zeros != 0 {
                time_replace_all_cases!(
                    replace,
                    clear_s,
                    encrypted_s,
                    encrypted_s_padding,
                    padding_zeros,
                    (
                        String,
                        clear_pattern,
                        encrypted_pattern,
                        encrypted_pattern_padded
                    ),
                    (
                        String,
                        clear_replace_pattern,
                        encrypted_replace_pattern,
                        encrypted_replace_pattern_padding
                    )
                );
            } else {
                time_replace_all_cases!(
                    replace,
                    clear_s,
                    encrypted_s,
                    encrypted_s_padding,
                    0,
                    (
                        String,
                        clear_pattern,
                        encrypted_pattern,
                        encrypted_pattern_padded
                    ),
                    (
                        String,
                        clear_replace_pattern,
                        encrypted_replace_pattern,
                        encrypted_replace_pattern_padding
                    )
                );
            }
        }
        _ => (),
    }

    let _test_key = gen_keys();
}

/// Times repeat for a clear integer argument.
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
    println!("time:                               {:?}", duration);
}

/// Identifier used to pattern match in macro definition.
pub type Clear = ();
pub type Encrypted = ();
pub fn return_clear() -> Clear {}
pub fn return_encrypted() -> Encrypted {}

/// Times repeat for an encrypted integer argument. It is required to provide a clear maximum of
/// repeatition max_n in order to bound the length of the result.
fn time_repeat_encrypted(
    clear_s: &str,
    encrypted_s: &FheString,
    clear_n: usize,
    max_n: usize,
    encrypted_n: &RadixCiphertext,
    padding_zeros: usize,
) {
    return_clear();
    return_encrypted();
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
    println!("time:                               {:?}", duration);
}
