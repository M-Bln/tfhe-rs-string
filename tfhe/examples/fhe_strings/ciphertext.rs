use crate::server_key::StringServerKey;
use std::string::FromUtf8Error;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

#[derive(Clone)]
pub struct FheAsciiChar(pub RadixCiphertext);

#[derive(Copy, Clone)]
pub enum Padding {
    None,
    Final,
    InitialAndFinal,
}

#[derive(Clone)]
pub enum ClearOrEncrypted<T, U> {
    Clear(T),
    Encrypted(U),
}

#[derive(Clone)]
pub enum FheStrLength {
    Clear(usize),
    Crypted(RadixCiphertext),
}

pub struct FheString {
    pub content: Vec<FheAsciiChar>,
    pub padding: Padding,
    pub length: FheStrLength,
}

#[derive(Debug)]
pub enum ConversionError {
    NonAsciiCharacters,
}

pub fn encrypt_ascii_vec(
    client_key: &RadixClientKey,
    utf8_vec: &Vec<u8>,
    padding: Padding,
    length: FheStrLength,
) -> Result<FheString, ConversionError> {
    if utf8_vec.iter().any(|c| !c.is_ascii()) {
        return Err(ConversionError::NonAsciiCharacters);
    }
    Ok(FheString {
        content: utf8_vec
            .iter()
            .map(|byte| FheAsciiChar(client_key.encrypt(*byte as u64)))
            .collect(),
        padding: padding,
        length: length,
    })
}

pub fn encrypt_str(client_key: &RadixClientKey, s: &str) -> Result<FheString, ConversionError> {
    encrypt_ascii_vec(
        client_key,
        &s.as_bytes().to_vec(),
        Padding::None,
        FheStrLength::Clear(s.len()),
    )
}

pub fn decrypt_fhe_ascii_vec(client_key: &RadixClientKey, s: &FheString) -> Vec<u8> {
    s.content
        .iter()
        .map(|crypted_char| client_key.decrypt::<u8>(&crypted_char.0))
        .collect::<Vec<u8>>()
}

pub fn decrypt_fhe_string(
    client_key: &RadixClientKey,
    s: &FheString,
) -> Result<String, FromUtf8Error> {
    string_from_padded_utf8(&decrypt_fhe_ascii_vec(client_key, s))
}

pub fn gen_keys() -> (RadixClientKey, StringServerKey) {
    let num_block = 4;
    match gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block) {
        (radix_client_key, server_key) => (
            radix_client_key,
            StringServerKey {
                integer_key: server_key,
            },
        ),
    }
}

/// Trim the initial and final '\0' bytes from a Vec<u8>
/// The resulting String starts directly after the last initial '\0'
/// if any, and ends just before the first '\0'.
pub fn string_from_padded_utf8(utf8_src: &Vec<u8>) -> Result<String, FromUtf8Error> {
    let range_start = utf8_src
        .iter()
        .position(|&c| c != b'\0')
        .unwrap_or(utf8_src.len()); // default to length if only `\0` are present
    let range_end = utf8_src[range_start..utf8_src.len()]
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len() - range_start); // default to length remaining if no trailing '\0'
    String::from_utf8(utf8_src[range_start..(range_end + range_start)].to_vec())
}

/// Produce a Vec<u8> from a str by adding padding_size trailing '\0'
pub fn null_padded_utf8_from_str(s: &str, padding_size: usize) -> Vec<u8> {
    let mut result: Vec<u8> = s.as_bytes().to_vec();
    result.append(&mut vec![0; padding_size]);
    result
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{encrypt_ascii_vec, gen_keys, FheStrLength, Padding};
    use lazy_static::lazy_static;
    use tfhe::integer::{RadixClientKey, ServerKey};

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, ServerKey) = match gen_keys() {
            (client_key, string_sks) => (client_key, string_sks.integer_key),
        };
    }

    #[test]
    fn test_encrypt_ascii_vec() {
        assert!(encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 0, 97, 98, 99, 100, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(4)
        )
        .is_ok());
        assert!(encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 0, 0xc3, 0x28, 0, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(2)
        )
        .is_err());
    }

    use crate::ciphertext::decrypt_fhe_ascii_vec;

    #[test]
    fn test_decrypt_encrypt_ascii_vec() {
        let encrypted_s = encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 0, 97, 98, 99, 100, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(4),
        )
        .unwrap();
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

    use crate::ciphertext::string_from_padded_utf8;

    #[test]
    fn test_string_from_padded_utf8() {
        let valid_utf8_src = vec![0, 0, 0, 0, 97, 98, 99, 100];
        let s = string_from_padded_utf8(&valid_utf8_src).unwrap();
        assert!(s.eq("abcd"));

        let invalid_utf8_src = vec![0, 0, 0xc3, 0x28, 0, 0];
        assert!(string_from_padded_utf8(&invalid_utf8_src).is_err());
    }

    use crate::ciphertext::null_padded_utf8_from_str;

    #[test]
    fn test_null_padded_utf8_from_str() {
        let padded_utf8 = null_padded_utf8_from_str("abc", 2);
        assert_eq!(padded_utf8, vec![97, 98, 99, 0, 0]);

        let truncated_utf8 = null_padded_utf8_from_str("abc", 0);
        assert_eq!(truncated_utf8, vec![97, 98, 99]);
    }
}
