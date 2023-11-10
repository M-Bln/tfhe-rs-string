use crate::ciphertext::{ClearOrEncryptedChar, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub const ASCII_WHITE_SPACE: u8 = 32;

impl StringServerKey {
    pub fn create_true(&self) -> RadixCiphertext {
        self.integer_key
            .scalar_add_parallelized(&self.integer_key.create_trivial_zero_radix(4), 1)
    }

    pub fn add_scalar_length(&self, length: &FheStrLength, scalar: u8) -> FheStrLength {
        match length {
            FheStrLength::Encrypted(encrypted_len) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_add_parallelized(&encrypted_len, scalar),
            ),
            FheStrLength::Clear(len) => FheStrLength::Clear(scalar as usize + len),
        }
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
                Padding::None => Padding::None,
                Padding::Final => Padding::Initial,
                Padding::Initial => Padding::Final,
                Padding::InitialAndFinal => Padding::InitialAndFinal,
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
        self.trim_start_clear_or_encrypted_char(s, &ClearOrEncryptedChar::Clear(character))
    }

    pub fn trim_start(&self, s: &FheString) -> FheString {
        self.trim_start_char(s, ASCII_WHITE_SPACE)
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
        character: &ClearOrEncryptedChar,
    ) -> FheString {
        let mut continue_triming = self.create_true();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut result_length: FheStrLength = s.length.clone();

        for c in s.content.iter() {
            self.integer_key.bitand_assign_parallelized(
                &mut continue_triming,
                &match s.padding {
                    Padding::InitialAndFinal => self.integer_key.bitor_parallelized(
                        &self.eq_clear_or_encrypted_char(c, character),
                        &self.eq_clear_or_encrypted_char(c, &ClearOrEncryptedChar::Clear(b'0')),
                    ),
                    _ => self.eq_clear_or_encrypted_char(c, character),
                },
            );
            self.add_assign_radix_length(&mut result_length, &continue_triming);
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

#[cfg(test)]
mod tests {
    use crate::ciphertext::{decrypt_fhe_string, encrypt_str, gen_keys, FheAsciiChar};
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, StringServerKey) = gen_keys();
    }

    #[test]
    fn test_trim_start_char() {
        let encrypted_str = encrypt_str(&KEYS.0, "ab").unwrap();
        let trimed_encrypted_str = KEYS.1.trim_start_char(&encrypted_str, b'a');
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "b");
    }

    #[test]
    fn test_trim_end_char() {
        let encrypted_str = encrypt_str(&KEYS.0, "ab").unwrap();
        let trimed_encrypted_str = KEYS.1.trim_end_char(&encrypted_str, b'b');
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "a");
    }

    #[test]
    fn test_trim_char() {
        let encrypted_str = encrypt_str(&KEYS.0, "aba").unwrap();
        let trimed_encrypted_str = KEYS.1.trim_char(&encrypted_str, b'a');
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "b");
    }

    #[test]
    fn test_trim() {
        let encrypted_str = encrypt_str(&KEYS.0, " b ").unwrap();
        let trimed_encrypted_str = KEYS.1.trim(&encrypted_str);
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "b");
    }    

    #[test]
    fn test_trim_start_encrypted() {
        let encrypted_str = encrypt_str(&KEYS.0, "ab").unwrap();
        let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'a'));
        let trimed_encrypted_str = KEYS.1.trim_start_encrypted(&encrypted_str, &encrypted_char);
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "b");
    }

    #[test]
    fn test_trim_end_encrypted() {
        let encrypted_str = encrypt_str(&KEYS.0, "ab").unwrap();
        let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'b'));
        let trimed_encrypted_str = KEYS.1.trim_end_encrypted(&encrypted_str, &encrypted_char);
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "a");
    }

    #[test]
    fn test_trim_encrypted() {
        let encrypted_str = encrypt_str(&KEYS.0, "bab").unwrap();
        let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'b'));
        let trimed_encrypted_str = KEYS.1.trim_encrypted(&encrypted_str, &encrypted_char);
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "a");
    }
}
