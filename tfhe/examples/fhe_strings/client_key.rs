use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;
use tfhe::core_crypto::prelude::UnsignedNumeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::integer::{RadixCiphertext, RadixClientKey};

#[derive(Serialize, Deserialize, Clone)]
pub struct StringClientKey {
    pub integer_key: RadixClientKey,
}

impl From<RadixClientKey> for StringClientKey {
    fn from(integer_key: RadixClientKey) -> Self {
        Self { integer_key }
    }
}

#[derive(Debug)]
pub enum ConversionError {
    NonAsciiCharacters,
    OutOfRange,
}

impl StringClientKey {
    /// Encrypt a string.
    pub fn encrypt_str(&self, s: &str) -> Result<FheString, ConversionError> {
        self.encrypt_ascii_vec(s.as_bytes(), Padding::None, FheStrLength::Clear(s.len()))
    }

    /// Encrypt a string and add `padding_size` encrypted padding zeros at the end of the string.
    pub fn encrypt_str_padding(
        &self,
        s: &str,
        padding_size: usize,
    ) -> Result<FheString, ConversionError> {
        if padding_size == 0 {
            self.encrypt_ascii_vec(
                &StringClientKey::null_padded_vec_from_str(s, padding_size),
                Padding::None,
                FheStrLength::Clear(s.len()),
            )
        } else {
            self.encrypt_ascii_vec(
                &StringClientKey::null_padded_vec_from_str(s, padding_size),
                Padding::Final,
                FheStrLength::Encrypted(self.integer_key.encrypt(s.len() as u64)),
            )
        }
    }

    /// Encrypt a string and add `padding_size` encrypted padding zeros dispatched randomly inside
    /// the content of the string. For performence reason strings should not be encrypted this way
    /// in applications. This function exists for testing purpose.
    pub fn encrypt_str_random_padding(
        &self,
        s: &str,
        padding_size: usize,
    ) -> Result<FheString, ConversionError> {
        if padding_size == 0 {
            self.encrypt_ascii_vec(
                &StringClientKey::null_padded_vec_from_str(s, padding_size),
                Padding::None,
                FheStrLength::Clear(s.len()),
            )
        } else {
            self.encrypt_ascii_vec(
                &StringClientKey::randomly_null_padded_vec_from_str(s, padding_size),
                Padding::Anywhere,
                FheStrLength::Encrypted(self.integer_key.encrypt(s.len() as u64)),
            )
        }
    }

    /// Decrypt a string.
    pub fn decrypt_string(&self, s: &FheString) -> Result<String, FromUtf8Error> {
        StringClientKey::string_from_padded_vec(self.decrypt_fhe_ascii_vec(s))
    }

    /// Encrypt a vector of ascii character (encoded as u8) and return an encrypted string. It does
    /// not perform any check and the returned string display the length and the padding passed as
    /// arguments.
    pub fn encrypt_ascii_vec(
        &self,
        ascii_vec: &[u8],
        padding: Padding,
        length: FheStrLength,
    ) -> Result<FheString, ConversionError> {
        if ascii_vec.iter().any(|c| !c.is_ascii()) {
            return Err(ConversionError::NonAsciiCharacters);
        }
        Ok(FheString {
            content: ascii_vec
                .iter()
                .map(|byte| self.encrypt_ascii_char(*byte))
                .collect(),
            padding,
            length,
        })
    }

    /// Encrypt a single character (encded as u8)
    pub fn encrypt_ascii_char(&self, ascii_char: u8) -> FheAsciiChar {
        FheAsciiChar(self.integer_key.encrypt(ascii_char))
    }

    pub fn decrypt_ascii_char(&self, encrypted_char: &FheAsciiChar) -> u8 {
        self.integer_key.decrypt::<u8>(&encrypted_char.0)
    }

    pub fn decrypt_integer(&self, encrypted_int: &RadixCiphertext) -> u32 {
        self.integer_key.decrypt::<u32>(encrypted_int)
    }

    pub fn encrypt_integer<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        n: T,
    ) -> RadixCiphertext {
        self.integer_key.encrypt::<T>(n)
    }

    pub fn decrypt_fhe_ascii_vec(&self, s: &FheString) -> Vec<u8> {
        s.content
            .iter()
            .map(|encrypted_char| self.decrypt_ascii_char(encrypted_char))
            .collect::<Vec<u8>>()
    }

    /// Produce a `Vec<u8>` from a `&str` by adding `padding_size` trailing `'\0'`
    pub fn null_padded_vec_from_str(s: &str, padding_size: usize) -> Vec<u8> {
        let mut result: Vec<u8> = s.as_bytes().to_vec();
        result.append(&mut vec![0; padding_size]);
        result
    }
    /// Create a vector with padding in `padding_size` zeros in random position in between the
    /// characters of s.
    pub fn randomly_null_padded_vec_from_str(s: &str, padding_size: usize) -> Vec<u8> {
        let result_length = s.len() + padding_size;
        let mut result: Vec<u8> = Vec::with_capacity(result_length);
        let mut current_s_index = 0;
        let mut current_padding_zeros = 0;
        for _ in 0..result_length {
            let choice = rand::thread_rng().gen_range(0..result_length);
            if (choice < s.len() || current_padding_zeros == padding_size)
                && current_s_index < s.len()
            {
                result.push(s.as_bytes()[current_s_index]);
                current_s_index += 1;
            } else {
                result.push(0);
                current_padding_zeros += 1;
            }
        }
        result
    }

    pub fn string_from_padded_vec(ascii_src: Vec<u8>) -> Result<String, FromUtf8Error> {
        let string_content: Vec<u8> = ascii_src
            .into_iter()
            .filter(|&c| c != 0)
            .collect::<Vec<u8>>();
        String::from_utf8(string_content)
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys_test;
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn test_randomly_null_padded_vec_from_str() {
        let padded_vec = StringClientKey::randomly_null_padded_vec_from_str("abcdef", 4);
        let s = StringClientKey::string_from_padded_vec(padded_vec).unwrap();
        assert_eq!(s, "abcdef");
        //assert_eq!(padded_vec, vec![0]);
    }

    #[test]
    fn test_encrypt_decrypt_random_padding() {
        let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("abc", 4).unwrap();
        let decrypted_str = CLIENT_KEY.decrypt_string(&encrypted_str).unwrap();
        assert_eq!(decrypted_str, "abc");
    }
}
