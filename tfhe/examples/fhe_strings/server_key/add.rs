use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::FhePattern;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn add(&self, mut s1: FheString, pattern: &impl FhePattern) -> FheString {
        pattern.push_to(self, s1)
    }
    pub fn add_encrypted(&self, mut s1: FheString, s2: &FheString) -> FheString {
        let result_padding: Padding = match (s1.padding, s2.padding) {
            (Padding::None, Padding::None) => Padding::None,
            (Padding::None, Padding::Final) => Padding::Final,
            (Padding::Initial, Padding::None) => Padding::Initial,
            (Padding::Initial, Padding::Final) => Padding::InitialAndFinal,
            _ => Padding::Anywhere,
        };

        let result_length = self.add_length(&s1.length, &s2.length);
        s1.content.append(&mut s2.content.clone());

        FheString {
            content: s1.content,
            length: result_length,
            padding: result_padding,
        }
    }

    pub fn add_clear(&self, mut s1: FheString, s2: &str) -> FheString {
        if s2.is_empty() {
            return s1;
        }
        let result_padding: Padding = match s1.padding {
            Padding::None => Padding::None,
            Padding::Initial => Padding::Initial,
            _ => Padding::Anywhere,
        };

        let result_length = self.add_scalar_to_length(&s1.length, s2.len());
        s1.content
            .append(&mut self.server_encrypt_str(s2).unwrap().content.clone());

        FheString {
            content: s1.content,
            length: result_length,
            padding: result_padding,
        }
    }

    pub fn add_clear_char(&self, mut s1: FheString, c: char) -> FheString {
        self.add_encrypted_char(s1, &self.server_encrypt_ascii_char(c))
    }

    pub fn add_encrypted_char(&self, mut s1: FheString, c: &FheAsciiChar) -> FheString {
        let result_padding: Padding = match s1.padding {
            Padding::None => Padding::None,
            Padding::Initial => Padding::Initial,
            _ => Padding::Anywhere,
        };

        let result_length = self.add_scalar_to_length(&s1.length, 1);
        s1.content.push(c.clone());

        FheString {
            content: s1.content,
            length: result_length,
            padding: result_padding,
        }
    }

    pub fn add_length(&self, l1: &FheStrLength, l2: &FheStrLength) -> FheStrLength {
        match (&l1, &l2) {
            (FheStrLength::Encrypted(encrypted_l1), l2) => self.add_radix_length(l2, encrypted_l1),
            (l1, FheStrLength::Encrypted(encrypted_l2)) => self.add_radix_length(l1, encrypted_l2),
            (FheStrLength::Clear(clear_l1), FheStrLength::Clear(clear_l2)) => {
                FheStrLength::Clear(*clear_l1 + *clear_l2)
            }
        }
    }

    pub fn add_scalar_to_length(&self, fhe_length: &FheStrLength, n: usize) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => FheStrLength::Clear(clear_length + n),
            FheStrLength::Encrypted(encrypted_length) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_add_parallelized(encrypted_length, n as u32),
            ),
        }
    }

    pub fn add_radix_to_length(
        &self,
        fhe_length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_add_parallelized(n, *clear_length as u32),
            ),
            FheStrLength::Encrypted(encrypted_length) => {
                FheStrLength::Encrypted(self.integer_key.add_parallelized(encrypted_length, n))
            }
        }
    }

    pub fn sub_radix_to_length(
        &self,
        fhe_length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => {
                let result_positive = self
                    .integer_key
                    .scalar_le_parallelized(n, *clear_length as u32);
                let radix_result = self.integer_key.cmux_parallelized(
                    &result_positive,
                    &self
                        .integer_key
                        .sub_parallelized(&self.create_n(*clear_length as u8), n),
                    &self.create_zero(),
                );
                FheStrLength::Encrypted(radix_result)
            }
            FheStrLength::Encrypted(encrypted_length) => {
                let result_positive = self.integer_key.le_parallelized(n, encrypted_length);
                let radix_result = self.integer_key.cmux_parallelized(
                    &result_positive,
                    &self.integer_key.sub_parallelized(encrypted_length, n),
                    &self.create_zero(),
                );
                FheStrLength::Encrypted(radix_result)
            }
        }
    }

    pub fn mult_length_by_radix(
        &self,
        fhe_length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_mul_parallelized(n, *clear_length as u32),
            ),
            FheStrLength::Encrypted(encrypted_length) => {
                FheStrLength::Encrypted(self.integer_key.mul_parallelized(encrypted_length, n))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys_test, FheAsciiChar, FheStrLength};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_fhe_add_char_pattern, test_fhe_add_string_pattern};
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    test_fhe_add_string_pattern!(add, "", "");
    test_fhe_add_string_pattern!(add, "ab", "");
    test_fhe_add_string_pattern!(add, "aezfb", "cdfzefzef");
    test_fhe_add_string_pattern!(add, "", "cd");

    test_fhe_add_char_pattern!(add, "", 'a');
    test_fhe_add_char_pattern!(add, "ab", 'a');
    test_fhe_add_char_pattern!(add, "aezfb", 'a');
    // #[test]
    // fn test_add_encrypted() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("ab", 0).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("bc", 0).unwrap();
    //     let add_str1_str2 = SERVER_KEY.add_encrypted(encrypted_str1, &encrypted_str2);
    //     let decrypted_str = CLIENT_KEY.decrypt_string(&add_str1_str2).unwrap();
    //     assert_eq!(decrypted_str, "abbc");
    // }

    // #[test]
    // fn test_add_encrypted() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("ab", 0).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("bc", 0).unwrap();
    //     let add_str1_str2 = SERVER_KEY.add_encrypted(encrypted_str1, &encrypted_str2);
    //     let decrypted_str = CLIENT_KEY.decrypt_string(&add_str1_str2).unwrap();
    //     assert_eq!(decrypted_str, "abbc");
    // }
}
