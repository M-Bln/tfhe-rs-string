use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn eq(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        self.compare(s1, s2, std::cmp::Ordering::Equal)
    }
    pub fn le(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        self.compare(s1, s2, std::cmp::Ordering::Less)
    }
    pub fn ge(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        self.compare(s1, s2, std::cmp::Ordering::Greater)
    }

    pub fn compare(
        &self,
        s1: &FheString,
        s2: &FheString,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        if operator == std::cmp::Ordering::Equal {
            match (&s1.length, &s2.length) {
                (&FheStrLength::Clear(l1), &FheStrLength::Clear(l2)) => {
                    if l1 != l2 {
                        return self.create_zero();
                    }
                }
                _ => (),
            }
        }
        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.compare_no_init_padding(s1, s2, operator)
            }
            (Padding::None | Padding::Final, _) => {
                self.compare_no_init_padding(s1, &self.remove_initial_padding(s2), operator)
            }
            (_, Padding::None | Padding::Final) => {
                self.compare_no_init_padding(&self.remove_initial_padding(s1), s2, operator)
            }
            _ => self.compare_no_init_padding(
                &self.remove_initial_padding(s1),
                &self.remove_initial_padding(s2),
                operator,
            ),
        }
    }

    pub fn compare_no_init_padding(
        &self,
        s1: &FheString,
        s2: &FheString,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.content.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &self.compare_char(&s1.content[n], &s2.content[n], operator),
            )
        }
        if s1.content.len() > s2.content.len() {
            return match operator {
                std::cmp::Ordering::Greater => result,
                _ => self.integer_key.bitand_parallelized(
                    &result,
                    &self
                        .integer_key
                        .scalar_eq_parallelized(&s1.content[s2.content.len()].0, 0),
                ),
            };
        }
        if s2.content.len() > s1.content.len() {
            return match operator {
                std::cmp::Ordering::Less => result,
                _ => self.integer_key.bitand_parallelized(
                    &result,
                    &self
                        .integer_key
                        .scalar_eq_parallelized(&s1.content[s2.content.len()].0, 0),
                ),
            };
        }
        result
    }

    pub fn compare_char(
        &self,
        c1: &FheAsciiChar,
        c2: &FheAsciiChar,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        match operator {
            std::cmp::Ordering::Equal => self.integer_key.eq_parallelized(&c1.0, &c2.0),
            std::cmp::Ordering::Less => self.integer_key.le_parallelized(&c1.0, &c2.0),
            std::cmp::Ordering::Greater => self.integer_key.ge_parallelized(&c1.0, &c2.0),
        }
    }

    pub fn scalar_compare_char(
        &self,
        c: &FheAsciiChar,
        scalar: u8,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        match operator {
            std::cmp::Ordering::Equal => self.integer_key.scalar_eq_parallelized(&c.0, scalar),
            std::cmp::Ordering::Less => self.integer_key.scalar_le_parallelized(&c.0, scalar),
            std::cmp::Ordering::Greater => self.integer_key.scalar_ge_parallelized(&c.0, scalar),
        }
    }

    /// Return the first element encrypting a non null character in content,
    /// replace it in content by an encryption of the null character.
    /// If all character are null, return an encryption of the null character.
    pub fn pop_first_non_zero_char(&self, content_slice: &mut [FheAsciiChar]) -> FheAsciiChar {
        let mut previous_is_padding_zero = self.create_true();
        let mut result = self.create_zero();

        for c in content_slice {
            let current_is_zero = self.integer_key.scalar_eq_parallelized(&c.0, 0);

            let first_non_null = self.integer_key.bitand_parallelized(
                &previous_is_padding_zero,
                &self.integer_key.bitnot_parallelized(&current_is_zero),
            );

            // Encrypt same value as c if c is the first no null encrypted char,
            // encrypt zero otherwise
            let to_sub = self.integer_key.mul_parallelized(&c.0, &first_non_null);

            // Compute the result
            self.integer_key
                .add_assign_parallelized(&mut result, &to_sub);

            // Update the value in content
            self.integer_key.sub_assign_parallelized(&mut c.0, &to_sub);

            // Update previous_is_padding_zero
            self.integer_key
                .bitand_assign_parallelized(&mut previous_is_padding_zero, &current_is_zero);
        }
        FheAsciiChar(result)
    }

    /// Replace the content of s with an encryption of the same string with the same
    /// and without initial padding.
    pub fn remove_initial_padding_assign(&self, s: &mut FheString) {
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut prev_content_slice = &mut s.content.clone()[..];
        for _ in 1..s.content.len() {
            result_content.push(self.pop_first_non_zero_char(prev_content_slice));
            prev_content_slice = &mut prev_content_slice[1..];
        }
        s.padding = Padding::Final;
        s.content = result_content;
    }

    /// Return an encryption of the same string, with the same content length,
    /// without initial padding.
    pub fn remove_initial_padding(&self, s: &FheString) -> FheString {
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut prev_content_slice = &mut s.content.clone()[..];
        for _ in 0..s.content.len() {
            result_content.push(self.pop_first_non_zero_char(prev_content_slice));
            prev_content_slice = &mut prev_content_slice[1..];
        }
        FheString {
            content: result_content,
            padding: Padding::Final,
            length: s.length.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{
        decrypt_fhe_string, encrypt_ascii_vec, gen_keys, FheStrLength, Padding,
    };
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, StringServerKey) = gen_keys();
    }

    #[test]
    fn test_pop_first_non_zero_char() {
        let mut encrypted_str = encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 97, 98, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        let poped_char = KEYS
            .1
            .pop_first_non_zero_char(&mut encrypted_str.content[..]);
        let decrypted_poped_char = KEYS.0.decrypt::<u8>(&poped_char.0);
        assert_eq!(decrypted_poped_char, 97);
        let decrypted_string = decrypt_fhe_string(&KEYS.0, &encrypted_str).unwrap();
        assert_eq!(decrypted_string, "b");
    }

    #[test]
    fn test_remove_initial_padding_assign() {
        let mut encrypted_str = encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 97],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        KEYS.1.remove_initial_padding_assign(&mut encrypted_str);
        let decrypted_char = KEYS.0.decrypt::<u8>(&encrypted_str.content[0].0);
        assert_eq!(decrypted_char, 97);
        assert_eq!(encrypted_str.padding, Padding::Final);

        let decrypted_string = decrypt_fhe_string(&KEYS.0, &encrypted_str).unwrap();
        assert_eq!(decrypted_string, "a");
    }

    #[test]
    fn test_remove_initial_padding() {
        let encrypted_str = encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 97],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        let encrypted_str_no_padding = KEYS.1.remove_initial_padding(&encrypted_str);
        let decrypted_char = KEYS.0.decrypt::<u8>(&encrypted_str_no_padding.content[0].0);
        assert_eq!(decrypted_char, 97);
        assert_eq!(encrypted_str_no_padding.padding, Padding::Final);

        let decrypted_string = decrypt_fhe_string(&KEYS.0, &encrypted_str_no_padding).unwrap();
        assert_eq!(decrypted_string, "a");
    }

    #[test]
    fn test_eq_no_init_padding() {
        let encrypted_str1 = encrypt_ascii_vec(
            &KEYS.0,
            &vec![97, 0, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(2),
        )
        .unwrap();
        let encrypted_str2 = encrypt_ascii_vec(
            &KEYS.0,
            &vec![97, 98],
            Padding::InitialAndFinal,
            FheStrLength::Clear(2),
        )
        .unwrap();
        let eq_str1_str2 = KEYS.1.eq_no_init_padding(&encrypted_str1, &encrypted_str2);
        let clear_eq_str1_str2 = KEYS.0.decrypt::<u8>(&eq_str1_str2);
        assert_eq!(clear_eq_str1_str2, 0);
    }

    #[test]
    fn test_eq() {
        let encrypted_str1 = encrypt_ascii_vec(
            &KEYS.0,
            &vec![97, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        let encrypted_str2 = encrypt_ascii_vec(
            &KEYS.0,
            &vec![98],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        let eq_str1_str2 = KEYS.1.eq(&encrypted_str1, &encrypted_str2);
        let clear_eq_str1_str2 = KEYS.0.decrypt::<u8>(&eq_str1_str2);
        assert_eq!(clear_eq_str1_str2, 0);
    }

    #[test]
    fn test_le_ge() {
        let encrypted_str1 = encrypt_ascii_vec(
            &KEYS.0,
            &vec![99, 110],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        let encrypted_str2 = encrypt_ascii_vec(
            &KEYS.0,
            &vec![99],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();

        let le_str1_str2 = KEYS.1.le(&encrypted_str1, &encrypted_str2);
        let ge_str1_str2 = KEYS.1.ge(&encrypted_str1, &encrypted_str2);

        let clear_le_str1_str2 = KEYS.0.decrypt::<u8>(&le_str1_str2);
        let clear_ge_str1_str2 = KEYS.0.decrypt::<u8>(&ge_str1_str2);

        assert_eq!(clear_le_str1_str2, 0);
        assert_eq!(clear_ge_str1_str2, 1);
    }
}
