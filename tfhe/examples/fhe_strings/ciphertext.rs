use std::str::Utf8Error;
use std::string::FromUtf8Error;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use crate::server_key::StringServerKey;

pub struct FheAsciiChar(pub RadixCiphertext);

pub type FheString = Vec<FheAsciiChar>;

#[derive(Debug)]
pub enum ConversionError {
    NonAsciiCharacters,
}

pub fn encrypt_ascii_vec(
    client_key: &RadixClientKey,
    utf8_vec: &Vec<u8>,
) -> Result<FheString, ConversionError> {
    if utf8_vec.iter().any(|c| !c.is_ascii()) {
        return Err(ConversionError::NonAsciiCharacters);
    }
    Ok(utf8_vec
        .iter()
        .map(|byte| FheAsciiChar(client_key.encrypt(*byte as u64)))
        .collect())
}

pub fn encrypt_str(client_key: &RadixClientKey, s: &str) -> Result<FheString, ConversionError> {
    encrypt_ascii_vec(client_key, &s.as_bytes().to_vec())
}

pub fn decrypt_fhe_ascii_vec(client_key: &RadixClientKey, s: &FheString) -> Vec<u8> {
    s.iter()
        .map(|crypted_char| client_key.decrypt::<u8>(&crypted_char.0))
        .collect::<Vec<u8>>()
}

pub fn decrypt_fhe_string(
    client_key: &RadixClientKey,
    s: &FheString,
) -> Result<String, FromUtf8Error> {
    String::from_utf8(decrypt_fhe_ascii_vec(client_key, s))
}

pub fn gen_keys() -> (RadixClientKey, StringServerKey) {
    let num_block = 4;
    match gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block){
	(radix_client_key, server_key) => (radix_client_key, StringServerKey{integer_key: server_key})
    }
}

/// Trim the initial and final '\0' bytes from a Vec<u8>, return a &str
pub fn str_from_null_padded_utf8(utf8_src: &Vec<u8>) -> Result<&str, Utf8Error> {
    let range_start = utf8_src
        .iter()
        .position(|&c| c != b'\0')
        .unwrap_or(utf8_src.len()); // default to length if only `\0` are present
    let range_end = utf8_src[range_start..utf8_src.len()]
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no trailing '\0'
    ::std::str::from_utf8(&utf8_src[range_start..(range_end + range_start)])
}

/// Produce a Vec<u8> of length length from str by adding trailing '\0'
/// if str.length() > length, the end of the string is truncated.
pub fn null_padded_utf8_from_str(s: &str, length: usize) -> Vec<u8> {
    let mut result: Vec<u8> = s.as_bytes().to_vec();
    if s.len() > length {
        result[0..length].to_vec()
    } else {
        result.append(&mut vec![0; length - s.len()]);
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{encrypt_ascii_vec, gen_keys};
    use lazy_static::lazy_static;
    use tfhe::integer::{RadixClientKey, ServerKey};

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, ServerKey) = match gen_keys() {
	    (client_key, string_sks) => (client_key, string_sks.integer_key)
	};
    }

    #[test]
    fn test_encrypt_ascii_vec() {
        assert!(encrypt_ascii_vec(&KEYS.0, &vec![0, 0, 97, 98, 99, 100, 0]).is_ok());
        assert!(encrypt_ascii_vec(&KEYS.0, &vec![0, 0, 0xc3, 0x28, 0, 0]).is_err());
    }

    use crate::ciphertext::decrypt_fhe_ascii_vec;

    #[test]
    fn test_decrypt_encrypt_ascii_vec() {
        let encrypted_s = encrypt_ascii_vec(&KEYS.0, &vec![0, 0, 97, 98, 99, 100, 0]).unwrap();
        let decrypted_s = decrypt_fhe_ascii_vec(&KEYS.0, &encrypted_s);
        println!("the decrypted vec is \"{:?}\"", decrypted_s);
        println!("it is expected to be \"[0,0,97,98,99,100,0]\"");
        assert_eq!(decrypted_s, vec![0, 0, 97, 98, 99, 100, 0]);
    }

    use crate::ciphertext::encrypt_str;

    #[test]
    fn test_encrypt() {
        assert!(encrypt_str(&KEYS.0, "Hello world!").is_ok())
    }

    use crate::ciphertext::decrypt_fhe_string;

    #[test]
    fn test_decrypt_encrypt() {
        let plain_text = "abc";
        let encrypted_str = encrypt_str(&KEYS.0, plain_text).unwrap();
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &encrypted_str).unwrap();
        println!(
            "the decrypted string is \"{}\", it is expected to be \"{}\"",
            decrypted_str, plain_text,
        )
    }

    use crate::ciphertext::str_from_null_padded_utf8;

    #[test]
    fn test_str_from_null_padded_utf8() {
        let valid_utf8_src = vec![0, 0, 0, 0, 97, 98, 99, 100, 0, 0, 0, 0, 0, 0];
        let s = str_from_null_padded_utf8(&valid_utf8_src).unwrap();
        assert!(s.eq("abcd"));

        let invalid_utf8_src = vec![0, 0, 0xc3, 0x28, 0, 0];
        assert!(str_from_null_padded_utf8(&invalid_utf8_src).is_err());
    }

    use crate::ciphertext::null_padded_utf8_from_str;

    #[test]
    fn test_null_padded_utf8_from_str() {
        let padded_utf8 = null_padded_utf8_from_str("abc", 5);
        assert_eq!(padded_utf8, vec![97, 98, 99, 0, 0]);

        let truncated_utf8 = null_padded_utf8_from_str("abcdef", 3);
        assert_eq!(truncated_utf8, vec![97, 98, 99]);
    }
}
