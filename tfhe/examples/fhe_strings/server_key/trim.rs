use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
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
            FheStrLength::Crypted(encrypted_len) => FheStrLength::Crypted(
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
            FheStrLength::Crypted(encrypted_len) => FheStrLength::Crypted(
                self.integer_key
                    .add_parallelized(&encrypted_len, &encrypted_int),
            ),
            FheStrLength::Clear(len) => FheStrLength::Crypted(
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

    pub fn trim_start_clear_char_no_padding(&self, s: &FheString, character: u8) -> FheString {
        let mut continue_triming = self.create_true();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut result_length: FheStrLength = s.length.clone();

        for c in s.content.iter() {
            self.integer_key.bitand_assign_parallelized(
                &mut continue_triming,
                &self.integer_key.scalar_eq_parallelized(&c.0, character),
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

    pub fn trim_start_encrypted_char_no_padding(
        &self,
        s: &FheString,
        encrypted_char: &FheAsciiChar,
    ) -> FheString {
        let mut continue_triming = self.create_true();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut result_length: FheStrLength = s.length.clone();

        for c in s.content.iter() {
            self.integer_key.bitand_assign_parallelized(
                &mut continue_triming,
                &self.integer_key.eq_parallelized(&c.0, &encrypted_char.0),
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
    fn test_trim_start_clear_char_no_padding() {
        let encrypted_str = encrypt_str(&KEYS.0, "ab").unwrap();
        let trimed_encrypted_str = KEYS
            .1
            .trim_start_clear_char_no_padding(&encrypted_str, b'a');
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "b");
    }

    #[test]
    fn test_trim_start_encrypted_char_no_padding() {
        let encrypted_str = encrypt_str(&KEYS.0, "ab").unwrap();
        let encrypted_char = FheAsciiChar(KEYS.0.encrypt(b'a'));
        let trimed_encrypted_str = KEYS
            .1
            .trim_start_encrypted_char_no_padding(&encrypted_str, &encrypted_char);
        let decrypted_str = decrypt_fhe_string(&KEYS.0, &trimed_encrypted_str).unwrap();
        assert_eq!(&decrypted_str, "b");
    }
}
