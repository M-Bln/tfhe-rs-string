use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn find_char(
        &self,
        s: &FheString,
        encrypted_char: &FheAsciiChar,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return (zero.clone(), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match: RadixCiphertext = self.eq_char(&s.content[n], &encrypted_char);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn find_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }

        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::None | Padding::Final) => {
                self.connected_find_unpadded_string(&self.remove_initial_padding(s), pattern)
            }
            (Padding::Anywhere, _) => self.connected_find_unpadded_string(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(pattern),
            ),
            (_, Padding::None | Padding::Final) => self.connected_find_unpadded_string(s, pattern),
            _ => self.connected_find_unpadded_string(s, &self.remove_initial_padding(pattern)),
        }
    }

    pub fn connected_find_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    //Should be called with `pattern.padding` either `Padding::None` or `Padding::Final`.
    pub fn find_from_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn find_from_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &self.min_length_radix(&s.length, from),
            &index,
        );
        (found, index)
    }

    pub fn rfind_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }

        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::None | Padding::Final) => {
                self.connected_rfind_unpadded_string(&self.remove_initial_padding(s), pattern)
            }
            (Padding::Anywhere, _) => self.connected_rfind_unpadded_string(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(pattern),
            ),
            (_, Padding::None | Padding::Final) => self.connected_rfind_unpadded_string(s, pattern),
            _ => self.connected_rfind_unpadded_string(s, &self.remove_initial_padding(pattern)),
        }
    }

    pub fn connected_rfind_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len() + 1).rev() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn rfind_from_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
        to: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.increment_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(to, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn rfind_from_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (from_greater_than_zero, zero),
            (0, _) => {
                return (
                    self.integer_key.bitand_parallelized(
                        &self.eq_clear_char(&pattern.content[0], 0),
                        &from_greater_than_zero,
                    ),
                    zero,
                )
            }
            _ => (),
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &self.min_length_radix(
                &s.length,
                &self.integer_key.scalar_sub_parallelized(from, 1),
            ),
            &index,
        );
        (found, index)
    }

    pub fn rfind_from_to_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
        to: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (from_greater_than_zero, zero),
            (0, _) => {
                return (
                    self.integer_key.bitand_parallelized(
                        &self.eq_clear_char(&pattern.content[0], 0),
                        &from_greater_than_zero,
                    ),
                    zero,
                )
            }
            _ => (),
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_ge_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &self.min_length_radix(&s.length, from),
            &index,
        );
        (found, index)
    }

    // pub fn rfind_from_final_padding_allow_empty_pattern(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    //     to: &RadixCiphertext,
    // ) -> (RadixCiphertext, RadixCiphertext) {
    //     let zero: RadixCiphertext = self.create_zero();
    //     let mut index = self.initial_index_rfind(&s.length);
    //     let mut found = zero;
    //     for n in (0..=s.content.len()).rev() {
    //         let current_match = self.integer_key.bitand_parallelized(
    //             &self.starts_with_encrypted_vec(&s.content[n..], pattern),
    //             &self.integer_key.scalar_gt_parallelized(to, n as u64),
    //         );
    //         self.integer_key
    //             .bitor_assign_parallelized(&mut found, &current_match);
    // 	    let increment_index = self.increment_index(s, n, &found);
    //         self.integer_key
    //             .sub_assign_parallelized(&mut index, &increment_index);
    //     }
    //     (found, index)
    // }

    pub fn min_length_radix(&self, length: &FheStrLength, to: &RadixCiphertext) -> RadixCiphertext {
        match length {
            FheStrLength::Clear(clear_length) => self
                .integer_key
                .scalar_min_parallelized(to, *clear_length as u64),
            FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(to, l),
        }
    }

    // pub fn min_length_radix_mi(&self, length: &FheStrLength, to: &RadixCiphertext) ->
    // RadixCiphertext {     match length {
    //         FheStrLength::Clear(clear_length) => self
    //             .integer_key
    //             .scalar_min_parallelized(to, *clear_length as u64),
    //         FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(to, l),
    //     }
    // }

    // pub fn rfind_from_final_padding_allow_empty_pattern(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    //     to: &RadixCiphertext,
    // ) -> (RadixCiphertext, RadixCiphertext) {
    //     let zero: RadixCiphertext = self.create_zero();
    //     let mut found = self.is_empty_encrypted(&pattern);
    //     let positive_to = self.integer_key.scalar_max_parallelized(to, 0);
    //     let upper_bound: RadixCiphertext = match &s.length {
    //         FheStrLength::Clear(clear_length) => self
    //             .integer_key
    //             .scalar_min_parallelized(&positive_to, *clear_length as u64),
    //         FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(&positive_to, l),
    //     };

    //     let mut index = self.integer_key.cmux_parallelized(
    //         &found,
    //         &upper_bound,
    //         &self.initial_index_rfind(&s.length),
    //     );

    //     for n in (0..s.content.len()).rev() {
    //         let increment_index = self.increment_index(s, n, &found);

    //         let current_match = self.integer_key.bitand_parallelized(
    //             &self.starts_with_encrypted_vec(&s.content[n..], pattern),
    //             &self.integer_key.scalar_gt_parallelized(to, n as u64),
    //         );
    //         self.integer_key
    //             .bitor_assign_parallelized(&mut found, &current_match);

    //         self.integer_key
    //             .sub_assign_parallelized(&mut index, &increment_index);
    //     }
    //     (found, index)
    // }

    pub fn initial_index_rfind_allow_empty_pattern(
        &self,
        length: &FheStrLength,
    ) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length - 1) as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_sub_parallelized(encrypted_length, 1),
        }
    }

    pub fn initial_index_rfind(&self, length: &FheStrLength) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n(*clear_length as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => encrypted_length.clone(),
        }
    }

    pub fn length_to_radix_plus_one(&self, length: &FheStrLength) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length + 1) as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_add_parallelized(encrypted_length, 1),
        }
    }

    pub fn increment_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        match s.padding {
            Padding::None | Padding::Final => self.integer_key.scalar_eq_parallelized(&found, 0),
            _ => self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_eq_parallelized(&found, 0),
                &self
                    .integer_key
                    .scalar_ne_parallelized(&s.content[content_index].0, 0),
            ),
        }
    }

    pub fn rincrement_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.integer_key.bitand_parallelized(
            &self.integer_key.scalar_eq_parallelized(&found, 0),
            &self
                .integer_key
                .scalar_ne_parallelized(&s.content[content_index].0, 0),
        )
    }

    pub fn decrement_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        match s.padding {
            Padding::None | Padding::Initial => self.integer_key.scalar_eq_parallelized(&found, 0),
            _ if content_index > s.content.len() => {
                self.integer_key.scalar_eq_parallelized(&found, 0)
            }
            _ => self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_eq_parallelized(&found, 0),
                &self
                    .integer_key
                    .scalar_ne_parallelized(&s.content[content_index].0, 0),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_test};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    // #[test]
    // fn test_find_char() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("cdf").unwrap();
    //     let encrypted_char = CLIENT_KEY.encrypt_ascii_char(102);
    //     let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char(105);
    //     let result = SERVER_KEY.find_char(&encrypted_str, &encrypted_char);
    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );
    //     let result2 = SERVER_KEY.find_char(&encrypted_str, &encrypted_char2);
    //     let clear_result2 = (
    //         CLIENT_KEY.decrypt_u8(&result2.0),
    //         CLIENT_KEY.decrypt_u8(&result2.1),
    //     );
    //     assert_eq!(clear_result, (1, 2));
    //     assert_eq!(clear_result2, (0, 3));
    // }

    // #[test]
    // fn test_find_string() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("cdf").unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("df", 1).unwrap();
    //     let encrypted_pattern2 = CLIENT_KEY.encrypt_str("cf").unwrap();
    //     let result = SERVER_KEY.find_string(&encrypted_str, &encrypted_pattern);
    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );
    //     let result2 = SERVER_KEY.find_string(&encrypted_str, &encrypted_pattern2);
    //     let clear_result2 = (
    //         CLIENT_KEY.decrypt_u8(&result2.0),
    //         CLIENT_KEY.decrypt_u8(&result2.1),
    //     );
    //     assert_eq!(clear_result, (1, 1));
    //     assert_eq!(clear_result2, (0, 2));
    // }

    // #[test]
    // fn test_rfind_string_with_padding() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("da", 1).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("", 1).unwrap();

    //     let result = SERVER_KEY.rfind_string(&encrypted_str, &encrypted_pattern);

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     assert_eq!(clear_result, (1, 2));
    // }

    // #[test]
    // fn test_rfind_string_with_padding2() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ddda", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("d", 1).unwrap();

    //     let result = SERVER_KEY.rfind_string(&encrypted_str, &encrypted_pattern);

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     assert_eq!(clear_result, (1, 2));
    // }

    // #[test]
    // fn test_rfind_from_final_padding_allow_empty_pattern() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_padding("abb", 2).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("a", 2).unwrap();
    //     let encrypted_index = SERVER_KEY.create_n(0);

    //     let result = SERVER_KEY.rfind_from_final_padding_allow_empty_pattern(
    //         &encrypted_str,
    //         &encrypted_pattern,
    //         &encrypted_index,
    //     );

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     assert_eq!(clear_result, (0, 0));
    // }

    #[test]
    fn test_rfind_from_final_padding_allow_empty_pattern2() {
        let encrypted_str = CLIENT_KEY.encrypt_str_padding("aa", 2).unwrap();
        let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("", 1).unwrap();

        let result = SERVER_KEY.rfind_from_final_padding_allow_empty_pattern(
            &encrypted_str,
            &encrypted_pattern,
            &SERVER_KEY.create_n(1),
        );

        let clear_result = (
            CLIENT_KEY.decrypt_u8(&result.0),
            CLIENT_KEY.decrypt_u8(&result.1),
        );

        assert_eq!(clear_result, (1, 0));
    }

    // #[test]
    // fn test_find_from_final_padding_allow_empty_pattern() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_padding("aa", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("a", 0).unwrap();
    //     let encrypted_index = SERVER_KEY.create_n(0);

    //     let result = SERVER_KEY.find_from_final_padding_allow_empty_pattern(
    //         &encrypted_str,
    //         &encrypted_pattern,
    //         &encrypted_index,
    //     );

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     assert_eq!(clear_result, (1, 0));
    // }

    // #[test]
    // fn test_find_from_final_padding_allow_empty_pattern2() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("ba").unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("", 0).unwrap();

    //     let result = SERVER_KEY.rfind_from_final_padding_allow_empty_pattern(
    //         &encrypted_str,
    //         &encrypted_pattern,
    //         &SERVER_KEY.create_n(3),
    //     );

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     assert_eq!(clear_result, (1, 2));
    // }

    // #[test]
    // fn test_rfind_from_final_padding2() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ddda", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("d", 1).unwrap();

    //     let result = SERVER_KEY.rfind_string(&encrypted_str, &encrypted_pattern);

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     assert_eq!(clear_result, (1, 2));
    // }
}
