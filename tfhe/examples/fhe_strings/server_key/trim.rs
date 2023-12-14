use crate::ciphertext::{ClearOrEncryptedChar, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub const ASCII_WHITE_SPACE: u8 = 32;

impl StringServerKey {
    pub fn create_true(&self) -> RadixCiphertext {
        self.integer_key
            .scalar_add_parallelized(&self.integer_key.create_trivial_zero_radix(4), 1)
    }

    pub fn create_zero(&self) -> RadixCiphertext {
        self.integer_key.create_trivial_zero_radix(4)
    }

    pub fn create_n(&self, n: u8) -> RadixCiphertext {
        self.integer_key
            .scalar_add_parallelized(&self.integer_key.create_trivial_zero_radix(4), n)
    }

    pub fn server_encrypt_str(&self, s: &str) -> Result<FheString, ConversionError> {
        self.server_encrypt_ascii_vec(&s.as_bytes().to_vec())
    }

    pub fn server_encrypt_ascii_char(&self, n: char) -> FheAsciiChar {
        FheAsciiChar(
            self.integer_key
                .scalar_add_parallelized(&self.integer_key.create_trivial_zero_radix(4), n as u8),
        )
    }

    pub fn server_encrypt_ascii_vec(
        &self,
        ascii_vec: &Vec<u8>,
    ) -> Result<FheString, ConversionError> {
        if ascii_vec.iter().any(|c| !c.is_ascii()) {
            return Err(ConversionError::NonAsciiCharacters);
        }
        Ok(FheString {
            content: ascii_vec
                .iter()
                .map(|c| self.server_encrypt_ascii_char(*c as char))
                .collect(),
            padding: Padding::None,
            length: FheStrLength::Clear(ascii_vec.len()),
        })
    }

    pub fn add_radix_length(
        &self,
        length: &FheStrLength,
        encrypted_int: &RadixCiphertext,
    ) -> FheStrLength {
        match length {
            FheStrLength::Encrypted(encrypted_len) => FheStrLength::Encrypted(
                self.integer_key
                    .add_parallelized(&encrypted_len, &encrypted_int),
            ),
            FheStrLength::Clear(len) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_add_parallelized(&encrypted_int, *len as u64),
            ),
        }
    }

    pub fn add_assign_radix_length(
        &self,
        length: &mut FheStrLength,
        encrypted_int: &RadixCiphertext,
    ) {
        *length = self.add_radix_length(&length, &encrypted_int);
    }

    pub fn eq_clear_or_encrypted_char(
        &self,
        c: &FheAsciiChar,
        character: &ClearOrEncryptedChar,
    ) -> RadixCiphertext {
        match character {
            ClearOrEncryptedChar::Clear(clear_char) => {
                self.integer_key.scalar_eq_parallelized(&c.0, *clear_char)
            }
            ClearOrEncryptedChar::Encrypted(ref encrypted_char) => {
                self.integer_key.eq_parallelized(&c.0, &encrypted_char.0)
            }
        }
    }

    pub fn reverse_string_content(&self, s: &FheString) -> FheString {
        FheString {
            content: s.content.clone().into_iter().rev().collect(),
            padding: match s.padding {
                Padding::Final => Padding::Initial,
                Padding::Initial => Padding::Final,
                padding => padding,
            },
            length: s.length.clone(),
        }
    }

    pub fn trim_end_char(&self, s: &FheString, character: u8) -> FheString {
        self.reverse_string_content(
            &self.trim_start_char(&self.reverse_string_content(s), character),
        )
    }

    pub fn trim_end(&self, s: &FheString) -> FheString {
        self.reverse_string_content(
            &self.trim_start_char(&self.reverse_string_content(s), ASCII_WHITE_SPACE),
        )
    }

    pub fn trim_end_encrypted(&self, s: &FheString, character: &FheAsciiChar) -> FheString {
        self.reverse_string_content(
            &self.trim_start_encrypted(&self.reverse_string_content(s), character),
        )
    }

    pub fn trim_char(&self, s: &FheString, character: u8) -> FheString {
        self.trim_end_char(&self.trim_start_char(s, character), character)
    }

    pub fn trim(&self, s: &FheString) -> FheString {
        self.trim_char(s, ASCII_WHITE_SPACE)
    }

    pub fn trim_encrypted(&self, s: &FheString, character: &FheAsciiChar) -> FheString {
        self.trim_end_encrypted(&self.trim_start_encrypted(s, character), character)
    }
    pub fn trim_start_char(&self, s: &FheString, character: u8) -> FheString {
	match s.padding {
	    Padding::None | Padding::Final => self.trim_start_clear_or_encrypted_char(&s, &ClearOrEncryptedChar::Clear(character)),
            _ => self.trim_start_clear_or_encrypted_char(&self.push_padding_to_end(&s), &ClearOrEncryptedChar::Clear(character))
	}
    }

 

    pub fn trim_start_encrypted(&self, s: &FheString, encrypted_char: &FheAsciiChar) -> FheString {
        self.trim_start_clear_or_encrypted_char(
            s,
            &ClearOrEncryptedChar::Encrypted(encrypted_char.clone()),
        )
    }

    pub fn trim_start_clear_or_encrypted_char(
        &self,
        s: &FheString,
	pattern: &ClearOrEncryptedChar,
    ) -> FheString {
        let mut continue_triming = self.create_true();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut result_length: FheStrLength = s.length.clone();

        for c in s.content.iter() {
            self.integer_key.bitand_assign_parallelized(
                &mut continue_triming,
		&self.eq_clear_or_encrypted_char(c, pattern),
            );
	     result_length = self.sub_radix_to_length(&result_length, &continue_triming);
            
            result_content.push(FheAsciiChar(self.integer_key.cmux_parallelized(
                &continue_triming,
                &self.create_zero(),
                &c.0,
            )))
        }

        FheString {
            content: result_content,
            padding: Padding::InitialAndFinal,
            length: result_length,
        }
    }    

    
    pub fn trim_start(
        &self,
        s: &FheString,
    ) -> FheString {
        let mut continue_triming = self.create_true();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut result_length: FheStrLength = s.length.clone();

        for c in s.content.iter() {
            self.integer_key.bitand_assign_parallelized(
                &mut continue_triming,
		&self.is_ascii_white_space(&c),
            );
	    result_length = self.sub_radix_to_length(&result_length, &continue_triming);
           
            result_content.push(FheAsciiChar(self.integer_key.cmux_parallelized(
                &continue_triming,
                &self.integer_key.create_trivial_zero_radix(4),
                &c.0,
            )))
        }

        FheString {
            content: result_content,
            padding: Padding::InitialAndFinal,
            length: result_length,
        }
    }    
}




// #[cfg(test)]
// mod tests {
//     use crate::ciphertext::{gen_keys, FheAsciiChar};
//     use crate::server_key::StringServerKey;
//     use crate::client_key::StringClientKey;
//     use lazy_static::lazy_static;
//     use tfhe::integer::RadixClientKey;

//     lazy_static! {
//         pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys();
//         pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
//         pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
//     }

//     #[test]
//     fn test_trim_start_char() {
//         let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ab",2).unwrap();
//         let trimed_encrypted_str = KEYS.1.trim_start_char(&encrypted_str, b'a');
//         let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
//         assert_eq!(&decrypted_str, "b");
//     }

//     #[test]
//     fn test_trim_start_encrypted() {
//         let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ab",2).unwrap();
//         let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'a'));
//         let trimed_encrypted_str = KEYS.1.trim_start_encrypted(&encrypted_str, &encrypted_char);
//         let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
//         assert_eq!(&decrypted_str, "b");
//     }

//     #[test]
//     fn test_trim_end_encrypted() {
//         let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ab",2).unwrap();
//         let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'b'));
//         let trimed_encrypted_str = KEYS.1.trim_end_encrypted(&encrypted_str, &encrypted_char);
//         let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
//         assert_eq!(&decrypted_str, "a");
//     }

//     #[test]
//     fn test_trim_encrypted() {
//         let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("bab",2).unwrap();
//         let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'b'));
//         let trimed_encrypted_str = KEYS.1.trim_encrypted(&encrypted_str, &encrypted_char);
//         let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
//         assert_eq!(&decrypted_str, "a");
//     }
// }
