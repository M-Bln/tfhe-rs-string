use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::integer_arg::FheIntegerArg;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

/// Creates a method with 3 arguments `&self, server_key, s`, that just calls a specified method
/// of `server_key`.
macro_rules! forward_to_server_key_method {
    ( $method:ident, $server_key_method: ident, $return_type:ty ) => {
        fn $method(&self, server_key: &StringServerKey, s: &FheString) -> $return_type {
            server_key.$server_key_method(s, self)
        }
    };
}

/// Creates a method with 4 arguments `&self, server_key, n, s`, that just calls a specified method
/// of `server_key`.
macro_rules! forward_splitn_to_server_key {
    ( $method:ident, $server_key_method: ident ) => {
        fn $method(
            &self,
            server_key: &StringServerKey,
            n: &impl FheIntegerArg,
            s: &FheString,
        ) -> FheSplit {
            server_key.$server_key_method(n, s, self)
        }
    };
}

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

    fn is_suffix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        self.is_prefix_of_string(server_key, &server_key.reverse_string_content(haystack))
    }

    fn strip_prefix_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, FheString);

    fn strip_suffix_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, FheString) {
        let (striped, reversed_result) =
            self.strip_prefix_in(server_key, &server_key.reverse_string_content(haystack));
        (striped, server_key.reverse_string_content(&reversed_result))
    }

    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString;

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString;

    fn find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext);

    fn rfind_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext);

    fn split_string(&self, server_key: &StringServerKey, s: &FheString) -> FheSplit;

    fn split_inclusive_string(&self, server_key: &StringServerKey, s: &FheString) -> FheSplit;

    fn split_terminator_string(&self, server_key: &StringServerKey, s: &FheString) -> FheSplit;

    fn rsplit_string(&self, server_key: &StringServerKey, s: &FheString) -> FheSplit;

    fn rsplit_terminator_string(&self, server_key: &StringServerKey, s: &FheString) -> FheSplit;

    fn splitn_string(
        &self,
        server_key: &StringServerKey,
        n: &impl FheIntegerArg,
        s: &FheString,
    ) -> FheSplit;

    fn rsplitn_string(
        &self,
        server_key: &StringServerKey,
        n: &impl FheIntegerArg,
        s: &FheString,
    ) -> FheSplit;

    fn is_contained_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        let mut result = server_key.create_zero();
        for i in 0..haystack.content.len() {
            server_key.integer_key.bitor_assign_parallelized(
                &mut result,
                &self.is_prefix_of_slice(server_key, &haystack.content[i..]),
            );
        }
        return result;
    }

    fn eq_string(&self, server_key: &StringServerKey, s: &FheString) -> RadixCiphertext;
}

impl FhePattern for &str {
    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString {
        let encrypted_self = server_key.server_encrypt_str(self).unwrap();
        server_key.insert_in_fhe_split_result_padded_anywhere(fhe_split, &encrypted_self)
    }

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString {
        server_key.add_clear(s, self)
    }

    fn is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        let mut result = server_key.create_true();
        if self.len() > haystack.len() {
            return server_key.create_zero();
        }
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
                &server_key.push_padding_to_end(haystack).content,
            ),
        }
    }

    fn is_suffix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        let reversed_string = self.chars().rev().collect::<String>();
        let reversed_self = reversed_string.as_str();
        reversed_self.is_prefix_of_string(server_key, &server_key.reverse_string_content(haystack))
    }

    fn strip_suffix_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, FheString) {
        let reversed_string = self.chars().rev().collect::<String>();
        let reversed_self = reversed_string.as_str();
        let (striped, reversed_result) =
            reversed_self.strip_prefix_in(server_key, &server_key.reverse_string_content(haystack));
        (striped, server_key.reverse_string_content(&reversed_result))
    }

    fn eq_string(&self, server_key: &StringServerKey, s: &FheString) -> RadixCiphertext {
        server_key.eq_clear(s, self)
    }

    // fn strip_prefix_in(&self, server_key: &StringServerKey, haystack: &FheString) -> FheString {
    // 	server_key.strip_clear_prefix(haystack, self)
    // }

    forward_to_server_key_method!(
        find_in,
        find_clear_string,
        (RadixCiphertext, RadixCiphertext)
    );
    forward_to_server_key_method!(
        rfind_in,
        rfind_clear_string,
        (RadixCiphertext, RadixCiphertext)
    );
    forward_to_server_key_method!(
        strip_prefix_in,
        strip_clear_prefix,
        (RadixCiphertext, FheString)
    );
    forward_to_server_key_method!(is_contained_in, contains_clear_string, RadixCiphertext);
    forward_to_server_key_method!(split_string, split_clear, FheSplit);
    forward_to_server_key_method!(split_inclusive_string, split_inclusive_clear, FheSplit);
    forward_to_server_key_method!(split_terminator_string, split_terminator_clear, FheSplit);
    forward_to_server_key_method!(rsplit_string, rsplit_clear, FheSplit);
    forward_to_server_key_method!(rsplit_terminator_string, rsplit_terminator_clear, FheSplit);

    forward_splitn_to_server_key!(splitn_string, splitn_clear_string);
    forward_splitn_to_server_key!(rsplitn_string, rsplitn_clear_string);
}

impl FhePattern for FheString {
    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString {
        server_key.insert_in_fhe_split_result_padded_anywhere(fhe_split, self)
    }

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString {
        server_key.add_encrypted(s, self)
    }

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
                        &server_key.eq_clear_char(&self.content[n], 0),
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
                let unpadded_needle = server_key.push_padding_to_end(self);
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

    fn eq_string(&self, server_key: &StringServerKey, s: &FheString) -> RadixCiphertext {
        server_key.eq_encrypted(self, s)
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
                &server_key.push_padding_to_end(haystack).content,
            ),
        }
    }

    fn is_suffix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        server_key
            .reverse_string_content(self)
            .is_prefix_of_string(server_key, &server_key.reverse_string_content(haystack))
    }

    fn strip_suffix_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, FheString) {
        let (striped, reversed_result) = server_key
            .reverse_string_content(self)
            .strip_prefix_in(server_key, &server_key.reverse_string_content(haystack));
        (striped, server_key.reverse_string_content(&reversed_result))
    }

    // fn strip_prefix_in(&self, server_key: &StringServerKey, haystack: &FheString) ->(Radix
    // FheString { 	server_key.strip_encrypted_prefix(self, haystack)
    // }

    forward_to_server_key_method!(
        strip_prefix_in,
        strip_encrypted_prefix,
        (RadixCiphertext, FheString)
    );
    forward_to_server_key_method!(find_in, find_string, (RadixCiphertext, RadixCiphertext));
    forward_to_server_key_method!(rfind_in, rfind_string, (RadixCiphertext, RadixCiphertext));
    forward_to_server_key_method!(is_contained_in, contains_string, RadixCiphertext);
    forward_to_server_key_method!(split_string, split_encrypted, FheSplit);
    forward_to_server_key_method!(rsplit_string, rsplit_encrypted, FheSplit);
    forward_to_server_key_method!(split_inclusive_string, split_inclusive_encrypted, FheSplit);
    forward_to_server_key_method!(
        split_terminator_string,
        split_terminator_encrypted,
        FheSplit
    );
    forward_to_server_key_method!(
        rsplit_terminator_string,
        rsplit_terminator_encrypted,
        FheSplit
    );

    forward_splitn_to_server_key!(splitn_string, splitn_encrypted_string);
    forward_splitn_to_server_key!(rsplitn_string, rsplitn_encrypted_string);
}

pub trait FheCharPattern {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext;

    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString;

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString;

    fn is_prefix_of_connected_string(
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

    fn is_prefix_of_string_any_padding(
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

impl<T: FheCharPattern> FhePattern for T {
    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString {
        FheCharPattern::insert_in(self, server_key, fhe_split)
    }

    fn eq_string(&self, server_key: &StringServerKey, s: &FheString) -> RadixCiphertext {
        server_key.create_zero()
    }

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString {
        FheCharPattern::push_to(self, server_key, s)
    }

    fn is_prefix_of_slice(
        &self,
        server_key: &StringServerKey,
        haystack_slice: &[FheAsciiChar],
    ) -> RadixCiphertext {
        if haystack_slice.len() == 0 {
            return server_key.create_zero();
        }
        self.fhe_eq(server_key, &haystack_slice[0])
    }

    fn is_prefix_of_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        match haystack.padding {
            Padding::None | Padding::Final => {
                self.is_prefix_of_slice(server_key, &haystack.content)
            }
            Padding::Initial | Padding::InitialAndFinal => {
                self.is_prefix_of_connected_string(server_key, haystack)
            }
            Padding::Anywhere => self.is_prefix_of_string_any_padding(server_key, haystack),
        }
    }

    forward_to_server_key_method!(
        strip_prefix_in,
        strip_char_prefix,
        (RadixCiphertext, FheString)
    );
    forward_to_server_key_method!(find_in, find_char, (RadixCiphertext, RadixCiphertext));
    forward_to_server_key_method!(rfind_in, rfind_char, (RadixCiphertext, RadixCiphertext));
    forward_to_server_key_method!(split_string, split_char, FheSplit);
    forward_to_server_key_method!(rsplit_string, rsplit_char, FheSplit);
    forward_to_server_key_method!(split_inclusive_string, split_inclusive_char, FheSplit);
    forward_to_server_key_method!(split_terminator_string, split_terminator_char, FheSplit);
    forward_to_server_key_method!(rsplit_terminator_string, rsplit_terminator_char, FheSplit);

    forward_splitn_to_server_key!(splitn_string, splitn_char);
    forward_splitn_to_server_key!(rsplitn_string, rsplitn_char);
}

impl FheCharPattern for char {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext {
        server_key.eq_clear_char(c, *self as u8)
    }

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString {
        server_key.add_clear_char(s, *self)
    }

    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString {
        let encrypted_self = server_key.server_encrypt_ascii_char(*self);
        server_key.insert_char_in_fhe_split_result_padded_anywhere(fhe_split, &encrypted_self)
    }
}

impl FheCharPattern for FheAsciiChar {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext {
        server_key.eq_char(c, &self)
    }

    fn push_to(&self, server_key: &StringServerKey, s: FheString) -> FheString {
        server_key.add_encrypted_char(s, self)
    }

    fn insert_in(&self, server_key: &StringServerKey, fhe_split: &FheSplit) -> FheString {
        server_key.insert_char_in_fhe_split_result_padded_anywhere(fhe_split, self)
    }
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
