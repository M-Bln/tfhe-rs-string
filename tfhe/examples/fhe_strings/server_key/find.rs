use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn find(
        &self,
        haystack: &FheString,
        pattern: &impl FhePattern,
    ) -> (RadixCiphertext, RadixCiphertext) {
        pattern.find_in(self, haystack)
    }

    pub fn find_char(
        &self,
        s: &FheString,
        char_pattern: &impl FheCharPattern,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return (zero.clone(), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match: RadixCiphertext = char_pattern.fhe_eq(self, &s.content[n]);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    // pub fn find(
    // 	&self,
    // 	s: &FheString,
    // 	pattern: &impl FhePattern,
    // ) -> (RadixCiphertext, RadixCiphertext) {

    // }

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

    pub fn find_clear_string(
        &self,
        s: &FheString,
        pattern: &str,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), zero),
            (content_length, pattern_length) if pattern_length > content_length => {
                return (zero.clone(), zero)
            }
            _ => (),
        }

        match s.padding {
            Padding::Anywhere => {
                self.connected_find_clear_string(&self.remove_initial_padding(s), pattern)
            }
            _ => self.connected_find_clear_string(s, pattern),
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

    pub fn connected_find_clear_string(
        &self,
        s: &FheString,
        pattern: &str,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            //            let current_match = self.starts_with_encrypted_vec(&s.content[n..],
            // pattern);
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

    macro_rules! test_option_index_char_pattern {
        ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
            paste::item! {

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                    let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }
    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                    let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_0_encrypted_char_" $pattern_arg>]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		    let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_2_encrypted_char_" $pattern_arg>]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		    let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}
            }
        };
    }

    macro_rules! test_option_index_string_pattern {
        ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
            paste::item! {

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                                     let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                                     let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
    		    let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                                     let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		    let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                                     let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}

    		#[test]
    		fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
    		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
    		    let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                                     let (clear_found, clear_fhe_result) = (CLIENT_KEY.decrypt_u8(&fhe_result.0), CLIENT_KEY.decrypt_u8(&fhe_result.1));
    		    match std_result {
    			Some(result) => {
    			    assert_eq!(result as u8, clear_fhe_result);
    			    assert_eq!(clear_found, 1);
    			},
    			None => assert_eq!(clear_found, 0)
    		    }

    		}
            }
        };
    }

    test_option_index_char_pattern!(find, "abc", 'a');
    test_option_index_char_pattern!(find, "abc", 'b');
    test_option_index_char_pattern!(find, "abc", 'c');
    test_option_index_char_pattern!(find, "abc", 'd');
    test_option_index_char_pattern!(find, "", 'b');

    test_option_index_string_pattern!(find, "abc", "a");
    test_option_index_string_pattern!(find, "abc", "b");
    test_option_index_string_pattern!(find, "abc", "c");
    test_option_index_string_pattern!(find, "abc", "ab");
    test_option_index_string_pattern!(find, "abc", "bc");
    test_option_index_string_pattern!(find, "abc", "abc");
    test_option_index_string_pattern!(find, "abc", "abcd");
    test_option_index_string_pattern!(find, "abc", "d");
    test_option_index_string_pattern!(find, "abc", "dzzzs");
    test_option_index_string_pattern!(find, "abc", "");
    test_option_index_string_pattern!(find, "", "abc");
    test_option_index_string_pattern!(find, "", "");
}
