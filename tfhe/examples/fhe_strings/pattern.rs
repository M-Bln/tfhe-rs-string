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

    fn char_find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext);

    fn char_rfind_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext);
}

impl FheCharPattern for char {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext {
        server_key.eq_clear_char(c, *self as u8)
    }

    fn char_find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        server_key.find_char(haystack, self)
    }

    fn char_rfind_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        server_key.rfind_char(haystack, self)
    }
}

impl FheCharPattern for FheAsciiChar {
    fn fhe_eq(&self, server_key: &StringServerKey, c: &FheAsciiChar) -> RadixCiphertext {
        server_key.eq_char(c, &self)
    }

    fn char_find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        server_key.find_char(haystack, self)
    }

    fn char_rfind_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        server_key.rfind_char(haystack, self)
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

    fn find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        self.char_find_in(server_key, haystack)
    }

    fn rfind_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        self.char_rfind_in(server_key, haystack)
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
