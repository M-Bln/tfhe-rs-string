use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::FhePattern;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

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

    fn is_contained_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        server_key.contains_clear_string(haystack, self)
    }

    fn find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        server_key.find_clear_string(haystack, self)
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

    fn is_contained_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> RadixCiphertext {
        server_key.contains_string(haystack, self)
    }

    fn find_in(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        server_key.find_string(haystack, self)
    }
}

impl StringServerKey {
    fn starts_with(&self, s: &FheString, pattern: &impl FhePattern) -> RadixCiphertext {
        pattern.is_prefix_of_string(self, s)
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
}
