use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub trait FhePattern {
    fn is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext;

    fn is_prefix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext;

    //    fn padding_required_for_is_prefix(&self) -> Padding;

    //    fn fhe_length(self) -> FheStrLength;

    fn is_contained_in(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        let mut result = server_key.create_zero();
        for i in 0..haystack.len() {
            server_key.integer_key.bitor_assign_parallelized(
                &mut result,
                &self.is_prefix_of_slice(server_key, &haystack[i..]),
            );
        }
        return result;
    }
}

pub trait FheCharPattern {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext;

    fn char_is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack_slice: &[FheAsciiChar],
    ) -> RadixCiphertext {
        if haystack_slice.len() == 0 {
            return server_key.create_zero();
        }
        self.fhe_eq(server_key, &haystack_slice[0])
    }

    fn char_is_prefix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        match haystack.padding {
            Padding::None | Padding::Final => {
                self.char_is_prefix_of_slice(server_key, &haystack.content)
            }
            Padding::Initial | Padding::InitialAndFinal => {
                self.char_is_prefix_of_connected_string(server_key, haystack)
            }
            Padding::Anywhere => self.char_is_prefix_of_string_any_padding(server_key, haystack),
        }
    }
    fn char_is_prefix_of_connected_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        let mut result = server_key.create_zero();
        let mut previous_char_is_null = server_key.create_true();
        for c in &haystack.content {
            let char_is_match = self.fhe_eq(server_key, &c);
            server_key.integer_key.bitor_assign_parallelized(
                &mut result,
                &server_key
                    .integer_key
                    .bitand_parallelized(&char_is_match, &previous_char_is_null),
            );
            previous_char_is_null = server_key.eq_clear_char(&c, 0);
        }
        result
    }

    fn char_is_prefix_of_string_any_padding(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        let mut result = server_key.create_zero();
        let mut before_first_char = server_key.create_true();
        for c in &haystack.content {
            let char_is_match = self.fhe_eq(server_key, c);
            let match_first_char = server_key
                .integer_key
                .bitand_parallelized(&before_first_char, &char_is_match);
            server_key
                .integer_key
                .bitor_assign_parallelized(&mut result, &match_first_char);
            server_key.integer_key.bitand_assign_parallelized(
                &mut before_first_char,
                &server_key.integer_key.scalar_eq_parallelized(&c.0, 0),
            );
        }
        result
    }
}

impl FheCharPattern for char {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext {
        server_key.eq_clear_char(c, *self as u8)
    }
}

impl FheCharPattern for FheAsciiChar {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext {
        server_key.eq_char(c, &self)
    }
}

impl<T: FheCharPattern> FhePattern for T {
    fn is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack_slice: &[FheAsciiChar],
    ) -> RadixCiphertext {
        self.char_is_prefix_of_slice(server_key, haystack_slice)
    }
    fn is_prefix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack_slice: &FheString,
    ) -> RadixCiphertext {
        self.char_is_prefix_of_string(server_key, haystack_slice)
    }
}

// impl FhePattern for char {
//     fn is_prefix_of_slice(
//         &self,
//         server_key: &StringServerKey,
//         haystack: &[FheAsciiChar],
//     ) -> RadixCiphertext {
//         if haystack.len() == 0 {
//             return server_key.create_zero();
//         }
//         server_key.eq_clear_char(&haystack[0], *self as u8)
//     }

//     fn is_prefix_of_string(
// 	&self,
// 	server_key: &StringServerKey,
// 	haystack: &FheString,
//     ) -> RadixCiphertext {
// 	match haystack.padding {
// 	    Padding::None | Padding::Final => self.is_prefix_of_slice(server_key, &haystack.content),
// 	    Padding::Initial | Padding::InitialAndFinal => {
// 		let mut result = server_key.create_zero();
// 		let mut previous_char_is_null = server_key.create_true();
// 		for c in &haystack.content {
// 		    let char_is_match = server_key.eq_clear_char(&c, *self as u8);
// 		    server_key.integer_key.bitor_assign_parallelized(
// 			&mut result,
// 			&server_key.integer_key.bitand_parallelized(
// 			    &char_is_match,
// 			    &previous_char_is_null,
// 			),
// 		    );
// 		    previous_char_is_null = server_key.eq_clear_char(&c, 0);
// 		}
// 		result
// 	    }
// 	    Padding::Anywhere => {
// 		let mut result = server_key.create_zero();
// 		let mut previous_char_is_null = server_key.create_true();
// 		for c in &haystack.content {
// 		    let char_is_match = server_key.eq_clear_char(&c, *self as u8);
// 		    let is_first_non_null_char = server_key.integer_key.bitand_parallelized(
// 			&previous_char_is_null,
// 			&server_key.integer_key.scalar_ne_parallelized(&c.0,0),
// 		    );
// 		    server_key.integer_key.bitor_assign_parallelized(
// 			&mut result,
// 			&server_key.integer_key.bitand_parallelized(
// 			    &char_is_match,
// 			    &is_first_non_null_char,
// 			),
// 		    );
// 		}
// 		result
// 	    }
// 	}
//     }

//     // fn fhe_length(self) -> FheStrLength {
//     //     FheStrLength::Clear(1)
//     // }
//     // fn padding_required_for_is_prefix(&self) -> Padding {
//     //     Padding::Final
//     // }
// }

// impl FhePattern for FheAsciiChar {
//     fn is_prefix_of_slice(
//         &self,
//         server_key: &StringServerKey,
//         haystack: &[FheAsciiChar],
//     ) -> RadixCiphertext {
//         if haystack.len() == 0 {
//             return server_key.create_zero();
//         }
//         server_key.eq_char(&haystack[0], self)
//     }
//     fn fhe_length(self) -> FheStrLength {
//         FheStrLength::Clear(1)
//     }
//     fn padding_required_for_is_prefix(&self) -> Padding {
//         Padding::Final
//     }
// }

impl FhePattern for &str {
    fn is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        let mut result = server_key.create_true();
        for n in 0..std::cmp::min(haystack.len(), self.len()) {
            server_key.integer_key.bitand_assign_parallelized(
                &mut result,
                &server_key.eq_clear_char(&haystack[n], self.as_bytes()[n]),
            )
        }
        result
    }

    fn is_prefix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        match &haystack.len() {
            FheStrLength::Clear(haystack_length) if *haystack_length < self.len() => {
                return server_key.create_zero()
            }
            _ if haystack.content.len() < self.len() => return server_key.create_zero(),
            _ => (),
        }
        match haystack.padding {
            Padding::None | Padding::Final => {
                self.is_prefix_of_slice(server_key, &haystack.content)
            }
            _ => self.is_prefix_of_slice(
                server_key,
                &server_key.remove_initial_padding(haystack).content,
            ),
        }
    }
}

impl FhePattern for FheString {
    fn is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        match &self.len() {
            FheStrLength::Clear(needle_length) if needle_length > &haystack.len() => {
                return server_key.create_zero()
            }
            _ => (),
        }
        let mut result = server_key.create_true();
        let max_needle_length = match &self.len() {
            FheStrLength::Clear(needle_length) => *needle_length,
            _ => self.content.len(),
        };
        match self.padding {
            Padding::None => {
                for n in 0..std::cmp::min(max_needle_length, haystack.len()) {
                    server_key.integer_key.bitand_assign_parallelized(
                        &mut result,
                        &server_key.eq_char(&haystack[n], &self.content[n]),
                    )
                }
            }
            Padding::Final => {
                for n in 0..std::cmp::min(max_needle_length, haystack.len()) {
                    let match_or_end_needle = server_key.integer_key.bitor_parallelized(
                        &server_key.eq_char(&haystack[n], &self.content[n]),
                        &server_key.eq_clear_char(&haystack[n], 0),
                    );
                    server_key
                        .integer_key
                        .bitand_assign_parallelized(&mut result, &match_or_end_needle)
                }
                if haystack.len() < max_needle_length {
                    server_key.integer_key.bitand_assign_parallelized(
                        &mut result,
                        &server_key.eq_clear_char(&self.content[haystack.len()], 0),
                    )
                }
            }
            _ => {
                let unpadded_needle = server_key.remove_initial_padding(self);
                for n in 0..std::cmp::min(max_needle_length, haystack.len()) {
                    let match_or_end_needle = server_key.integer_key.bitor_parallelized(
                        &server_key.eq_char(&haystack[n], &unpadded_needle.content[n]),
                        &server_key.eq_clear_char(&unpadded_needle.content[n], 0),
                    );
                    server_key
                        .integer_key
                        .bitand_assign_parallelized(&mut result, &match_or_end_needle)
                }
                if haystack.len() < max_needle_length {
                    server_key.integer_key.bitand_assign_parallelized(
                        &mut result,
                        &server_key.eq_clear_char(&unpadded_needle.content[haystack.len()], 0),
                    )
                }
            }
        }
        result
    }

    fn is_prefix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        match &(self.len(), haystack.len()) {
            (FheStrLength::Clear(needle_length), FheStrLength::Clear(haystack_length))
                if *needle_length > *haystack_length =>
            {
                return server_key.create_zero()
            }
            (FheStrLength::Clear(needle_length), _) if *needle_length > haystack.content.len() => {
                return server_key.create_zero()
            }
            _ => (),
        }
        match haystack.padding {
            Padding::None | Padding::Final => {
                self.is_prefix_of_slice(server_key, &haystack.content)
            }
            _ => self.is_prefix_of_slice(
                server_key,
                &server_key.remove_initial_padding(haystack).content,
            ),
        }
    }
}

impl StringServerKey {
    fn starts_with(&self, s: &FheString, pattern: &impl FhePattern) -> RadixCiphertext {
        pattern.is_prefix_of_string(self, s)
    }

    fn contains(&self, s: &FheString, pattern: &impl FhePattern) -> RadixCiphertext {
        pattern.is_contained_in(self, &s.content)
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

    pub fn test_starts_with_string_padding(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
        string_padding: usize,
        pattern_padding: usize,
    ) {
        let std_starts_with = s.starts_with(pattern);
        let encrypted_s = client_key
            .encrypt_str_random_padding(s, string_padding)
            .unwrap();
        let encrypted_pattern = client_key
            .encrypt_str_random_padding(pattern, pattern_padding)
            .unwrap();
        let fhe_starts_with_encrypted = server_key.starts_with(&encrypted_s, &encrypted_pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_starts_with_encrypted),
            std_starts_with as u8
        );
        let fhe_starts_with_clear = server_key.starts_with(&encrypted_s, &pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_starts_with_clear),
            std_starts_with as u8
        );
    }

    pub fn test_starts_with_string(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
    ) {
        test_starts_with_string_padding(client_key, server_key, s, pattern, 0, 0);
        test_starts_with_string_padding(client_key, server_key, s, pattern, 2, 0);
        test_starts_with_string_padding(client_key, server_key, s, pattern, 0, 2);
        test_starts_with_string_padding(client_key, server_key, s, pattern, 2, 2);
    }

    pub fn test_starts_with_char_padding(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: char,
        string_padding: usize,
    ) {
        let std_starts_with = s.starts_with(pattern);
        let mut encrypted_s = client_key
            .encrypt_str_random_padding(s, string_padding)
            .unwrap();
        let encrypted_pattern = client_key.encrypt_ascii_char(pattern as u8);
        let mut fhe_starts_with_encrypted =
            server_key.starts_with(&encrypted_s, &encrypted_pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_starts_with_encrypted),
            std_starts_with as u8
        );
        let mut fhe_starts_with_clear = server_key.starts_with(&encrypted_s, &pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_starts_with_clear),
            std_starts_with as u8
        );

        encrypted_s = client_key.encrypt_str_padding(s, string_padding).unwrap();
        fhe_starts_with_encrypted = server_key.starts_with(&encrypted_s, &encrypted_pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_starts_with_encrypted),
            std_starts_with as u8
        );
        let mut fhe_starts_with_clear = server_key.starts_with(&encrypted_s, &pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_starts_with_clear),
            std_starts_with as u8
        );
    }

    pub fn test_starts_with_char(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: char,
    ) {
        test_starts_with_char_padding(client_key, server_key, s, pattern, 0);
        test_starts_with_char_padding(client_key, server_key, s, pattern, 5);
    }

    #[test]
    fn test_starts_with_char0() {
        test_starts_with_char(&CLIENT_KEY, &SERVER_KEY, "abc", 'a');
    }

    #[test]
    fn test_starts_with_char1() {
        test_starts_with_char(&CLIENT_KEY, &SERVER_KEY, "abc", 'b');
    }

    #[test]
    fn test_starts_with_char2() {
        test_starts_with_char(&CLIENT_KEY, &SERVER_KEY, "", 'b');
    }

    #[test]
    fn test_starts_with_string0() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "a");
    }

    #[test]
    fn test_starts_with_string1() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "ab");
    }

    #[test]
    fn test_starts_with_string2() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "abc");
    }

    #[test]
    fn test_starts_with_string3() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "abcd");
    }

    #[test]
    fn test_starts_with_string4() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "d");
    }

    #[test]
    fn test_starts_with_string5() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "dzzzs");
    }

    #[test]
    fn test_starts_with_string6() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "abc", "");
    }

    #[test]
    fn test_starts_with_string7() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "", "abc");
    }

    #[test]
    fn test_starts_with_string8() {
        test_starts_with_string(&CLIENT_KEY, &SERVER_KEY, "", "");
    }

    // #[test]
    // fn test_starts_with_clear_char() {
    //     let s = CLIENT_KEY.encrypt_str("abc").unwrap();
    //     let result = SERVER_KEY.starts_with(&s, &'b');
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
    //     let result2 = SERVER_KEY.starts_with(&s, &'a');
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    // }

    // #[test]
    // fn test_contains_clear_char() {
    //     let s = CLIENT_KEY.encrypt_str_random_padding("abc", 2).unwrap();
    //     let result = SERVER_KEY.contains(&s, &'d');
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
    //     let result2 = SERVER_KEY.contains(&s, &'b');
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    // }

    // #[test]
    // fn test_starts_with_encrypted_char() {
    //     let s = CLIENT_KEY.encrypt_str("abc").unwrap();
    //     let encrypted_char = CLIENT_KEY.encrypt_ascii_char('b' as u8);
    //     let result = SERVER_KEY.starts_with(&s, &encrypted_char);
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
    //     let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char('a' as u8);
    //     let result2 = SERVER_KEY.starts_with(&s, &encrypted_char2);
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    // }

    // #[test]
    // fn test_contains_encrypted_char() {
    //     let s = CLIENT_KEY.encrypt_str_random_padding("abc", 2).unwrap();
    //     let encrypted_char = CLIENT_KEY.encrypt_ascii_char('d' as u8);
    //     let result = SERVER_KEY.contains(&s, &encrypted_char);
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
    //     let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char('a' as u8);
    //     let result2 = SERVER_KEY.contains(&s, &encrypted_char2);
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    // }
}
