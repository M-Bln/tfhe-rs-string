use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::FhePattern;
use crate::server_key::StringServerKey;
use tfhe::integer::{RadixCiphertext, BooleanBlock};

impl StringServerKey {
    pub fn contains(&self, s: &FheString, pattern: &impl FhePattern) -> BooleanBlock {
        pattern.is_contained_in(self, s)
    }

    pub fn contains_string(&self, s: &FheString, pattern: &FheString) -> BooleanBlock {
        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::Final | Padding::None) => {
                self.contains_unpadded_string(&self.push_padding_to_end(s), pattern)
            }
            (Padding::Anywhere, _) => self.contains_unpadded_string(
                &self.push_padding_to_end(s),
                &self.push_padding_to_end(pattern),
            ),
            (_, Padding::Final | Padding::None) => self.contains_unpadded_string(s, pattern),
            _ => self.contains_unpadded_string(s, &self.push_padding_to_end(pattern)),
        }
    }

    pub fn contains_clear_string(&self, s: &FheString, pattern: &str) -> BooleanBlock {
        match (s.content.len(), pattern.len()) {
            (0, 0) => return self.create_true(),
            (0, _) => return self.create_false(),
            (string_length, pattern_length) if pattern_length > string_length => {
                return self.create_false()
            }
            _ => (),
        }
        match s.padding {
            Padding::Anywhere => {
                self.connected_contains_clear_string(&self.push_padding_to_end(s), pattern)
            }
            _ => self.connected_contains_clear_string(s, pattern),
        }
    }

    fn connected_contains_clear_string(&self, s: &FheString, pattern: &str) -> BooleanBlock {
        let mut result = self.create_false();
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            //let current_match = self.starts_with_vec_clear(&s.content[n..], pattern);
            self.integer_key
                .boolean_bitor_assign(&mut result, &current_match);
        }
        result
    }

    pub fn contains_unpadded_string(&self, s: &FheString, pattern: &FheString) -> BooleanBlock {
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return self.create_true(),
            (0, _) => return self.eq_clear_char(&pattern.content[0], 0),
            _ => (),
        }
        let mut result = self.create_false();
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            //let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .boolean_bitor_assign(&mut result, &current_match);
        }
        result
    }

    /// Check if s encrypts a string which has the string encrypted by prefix as a prefix. The
    /// function assumes that both s and prefix do not have initial padding zeros. Return an
    /// encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn starts_with_encrypted_vec(
        &self,
        s: &[FheAsciiChar],
        prefix: &FheString,
    ) -> BooleanBlock {
        // First the overlapping content are compared
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.len(), prefix.content.len()) {
            self.integer_key.boolean_bitand_assign(
                &mut result,
                &match prefix.padding {
                    Padding::None => {
                        self.compare_char(&s[n], &prefix.content[n], std::cmp::Ordering::Equal)
                    }
                    _ => self.integer_key.boolean_bitor(
                        &self.compare_char(&s[n], &prefix.content[n], std::cmp::Ordering::Equal),
                        &self
                            .integer_key
                            .scalar_eq_parallelized(&prefix.content[n].0, 0),
                    ),
                },
            )
        }
        // If prefix content size is greater than s content size, check if the extra characters are
        // padding zeros
        if prefix.content.len() > s.len() {
            return self.integer_key.boolean_bitand(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&prefix.content[s.len()].0, 0),
            );
        }
        result
    }

    pub fn starts_with_vec_clear(&self, s: &[FheAsciiChar], prefix: &str) -> BooleanBlock {
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.len(), prefix.len()) {
            self.integer_key.boolean_bitand_assign(
                &mut result,
                &self.compare_clear_char(&s[n], prefix.as_bytes()[n], std::cmp::Ordering::Equal),
            )
        }
        result
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

    macro_rules! test_char_pattern {
        ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
            paste::item! {

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_0_clear_char_" $pattern_arg>]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_char_" $pattern_arg>]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_0_encrypted_char_" $pattern_arg>]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		    let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_2_encrypted_char_" $pattern_arg>]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
		    let encrypted_pattern = CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}
            }
        };
    }

    macro_rules! test_string_pattern {
        ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
            paste::item! {

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_0_clear_string_" $pattern_arg>]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_random_padding_2_clear_string_" $pattern_arg>]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_0_" $pattern_arg "_padding_0">]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str(&$string_arg).unwrap();
		    let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_0">]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
		    let encrypted_pattern = CLIENT_KEY.encrypt_str(&$pattern_arg).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}

		#[test]
		fn [<"test_" $method "_" $string_arg "_padding_2_" $pattern_arg "_padding_2">]() {
		    let std_result = $string_arg.$method($pattern_arg);
                    let encrypted_s = CLIENT_KEY.encrypt_str_random_padding(&$string_arg, 2).unwrap();
		    let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding(&$pattern_arg, 2).unwrap();
                    let fhe_result = SERVER_KEY.$method(&encrypted_s, &encrypted_pattern);
                    let clear_fhe_result = CLIENT_KEY.decrypt_u8(&fhe_result);
		    assert_eq!(std_result as u8, clear_fhe_result);
		}
            }
        };
    }

    test_char_pattern!(contains, "abc", 'a');
    test_char_pattern!(contains, "abc", 'b');
    test_char_pattern!(contains, "abc", 'c');
    test_char_pattern!(contains, "abc", 'd');
    test_char_pattern!(contains, "", 'b');

    test_string_pattern!(contains, "abc", "a");
    test_string_pattern!(contains, "abc", "b");
    test_string_pattern!(contains, "abc", "c");
    test_string_pattern!(contains, "abc", "ab");
    test_string_pattern!(contains, "abc", "bc");
    test_string_pattern!(contains, "abc", "abc");
    test_string_pattern!(contains, "abc", "abcd");
    test_string_pattern!(contains, "abc", "d");
    test_string_pattern!(contains, "abc", "dzzzs");
    test_string_pattern!(contains, "abc", "");
    test_string_pattern!(contains, "", "abc");
    test_string_pattern!(contains, "", "");
}
