use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;
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
    pub fn encrypt_str(&self, s: &str) -> Result<FheString, ConversionError> {
        self.encrypt_ascii_vec(
            &s.as_bytes().to_vec(),
            Padding::None,
            FheStrLength::Clear(s.len()),
        )
    }

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

    pub fn decrypt_string(&self, s: &FheString) -> Result<String, FromUtf8Error> {
        StringClientKey::string_from_padded_vec(self.decrypt_fhe_ascii_vec(s))
    }

    pub fn encrypt_ascii_vec(
        &self,
        ascii_vec: &Vec<u8>,
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
            padding: padding,
            length: length,
        })
    }

    pub fn encrypt_ascii_char(&self, ascii_char: u8) -> FheAsciiChar {
        FheAsciiChar(self.integer_key.encrypt(ascii_char as u8))
    }

    pub fn decrypt_ascii_char(&self, encrypted_char: &FheAsciiChar) -> u8 {
        self.integer_key.decrypt::<u8>(&encrypted_char.0)
    }

    pub fn decrypt_u8(&self, encrypted_int: &RadixCiphertext) -> u8 {
        self.integer_key.decrypt::<u8>(&encrypted_int)
    }

    pub fn encrypt_u8(&self, n: u8) -> RadixCiphertext {
        self.integer_key.encrypt(n)
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

    pub fn randomly_null_padded_vec_from_str(s: &str, padding_size: usize) -> Vec<u8> {
        let result_length = s.len() + padding_size;
        let mut result: Vec<u8> = Vec::with_capacity(result_length);
        let mut current_s_index = 0;
        let mut current_padding_zeros = 0;
        for n in 0..result_length {
            let choice = rand::thread_rng().gen_range(0..result_length);
            if (choice < s.len() || current_padding_zeros == padding_size)
                && current_s_index < s.len()
            {
                result.push(s.as_bytes()[current_s_index]);
                current_s_index = current_s_index + 1;
            } else {
                result.push(0);
                current_padding_zeros = current_padding_zeros + 1;
            }
        }
        result
    }

    // /// Trim the initial and final '\0' bytes from a Vec<u8>
    // /// The resulting String starts directly after the last initial '\0'
    // /// if any, and ends just before the first '\0'.
    // pub fn fstring_from_padded_vec(ascii_src: &Vec<u8>) -> Result<String, FromUtf8Error> {
    //     let range_start = ascii_src
    //         .iter()
    //         .position(|&c| c != b'\0')
    //         .unwrap_or(ascii_src.len()); // default to length if only `\0` are present
    //     let range_end = ascii_src[range_start..ascii_src.len()]
    //         .iter()
    //         .position(|&c| c == b'\0')
    //         .unwrap_or(ascii_src.len() - range_start); // default to length remaining if no
    // trailing '\0'     String::from_utf8(ascii_src[range_start..(range_end +
    // range_start)].to_vec()) }

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
    use crate::ciphertext::{gen_keys_test, FheStrLength, Padding};
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

    #[test]
    fn test_integer_size() {
        let big_int = CLIENT_KEY.integer_key.encrypt(250 as u32);
        let bigger_int = SERVER_KEY.integer_key.scalar_add_parallelized(&big_int, 30);
        assert_eq!(CLIENT_KEY.integer_key.decrypt::<u32>(&bigger_int), 280);
    }
}
