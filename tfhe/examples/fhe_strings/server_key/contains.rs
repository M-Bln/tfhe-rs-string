use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::FhePattern;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn contains(&self, s: &FheString, pattern: &impl FhePattern) -> RadixCiphertext {
        pattern.is_contained_in(self, s)
    }

    pub fn contains_string(&self, s: &FheString, pattern: &FheString) -> RadixCiphertext {
        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::Final | Padding::None) => {
                self.contains_unpadded_string(&self.remove_initial_padding(s), pattern)
            }
            (Padding::Anywhere, _) => self.contains_unpadded_string(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(pattern),
            ),
            (_, Padding::Final | Padding::None) => self.contains_unpadded_string(s, pattern),
            _ => self.contains_unpadded_string(s, &self.remove_initial_padding(pattern)),
        }
    }

    pub fn contains_clear_string(&self, s: &FheString, pattern: &str) -> RadixCiphertext {
        match (s.content.len(), pattern.len()) {
            (0, 0) => return self.create_true(),
            (0, _) => return self.create_zero(),
            (string_length, pattern_length) if pattern_length > string_length => {
                return self.create_zero()
            }
            _ => (),
        }
        match s.padding {
            Padding::Anywhere => {
                self.connected_contains_clear_string(&self.remove_initial_padding(s), pattern)
            }
            _ => self.connected_contains_clear_string(s, pattern),
        }
    }

    fn connected_contains_clear_string(&self, s: &FheString, pattern: &str) -> RadixCiphertext {
        let mut result = self.create_zero();
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            //   let current_match = self.starts_with_vec_clear(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut result, &current_match);
        }
        result
    }

    pub fn contains_unpadded_string(&self, s: &FheString, pattern: &FheString) -> RadixCiphertext {
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return self.create_true(),
            (0, _) => return self.eq_clear_char(&pattern.content[0], 0),
            _ => (),
        }
        let mut result = self.create_zero();
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            self.integer_key
                .bitor_assign_parallelized(&mut result, &current_match);
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
    ) -> RadixCiphertext {
        // First the overlapping content are compared
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.len(), prefix.content.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &match prefix.padding {
                    Padding::None => {
                        self.compare_char(&s[n], &prefix.content[n], std::cmp::Ordering::Equal)
                    }
                    _ => self.integer_key.bitor_parallelized(
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
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&prefix.content[s.len()].0, 0),
            );
        }
        result
    }

    pub fn starts_with_vec_clear(&self, s: &[FheAsciiChar], prefix: &str) -> RadixCiphertext {
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.len(), prefix.len()) {
            self.integer_key.bitand_assign_parallelized(
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

    pub fn test_contains_string_padding(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
        string_padding: usize,
        pattern_padding: usize,
    ) {
        let std_contains = s.contains(pattern);
        let encrypted_s = client_key
            .encrypt_str_random_padding(s, string_padding)
            .unwrap();
        // let encrypted_pattern = client_key
        //     .encrypt_str_random_padding(pattern, pattern_padding)
        //     .unwrap();
        // let fhe_contains_encrypted = server_key.contains(&encrypted_s, &encrypted_pattern);
        // assert_eq!(
        //    client_key.decrypt_u8(&fhe_contains_encrypted),
        //    std_contains as u8
        // );
        let fhe_contains_clear = server_key.contains(&encrypted_s, &pattern);
        // assert_eq!(
        //    client_key.decrypt_u8(&fhe_contains_clear),
        //    std_contains as u8
        // );
    }

    pub fn test_contains_string(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
    ) {
        test_contains_string_padding(client_key, server_key, s, pattern, 0, 0);
        test_contains_string_padding(client_key, server_key, s, pattern, 2, 0);
        test_contains_string_padding(client_key, server_key, s, pattern, 0, 2);
        test_contains_string_padding(client_key, server_key, s, pattern, 2, 2);
    }

    pub fn test_contains_char_padding(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: char,
        string_padding: usize,
    ) {
        let std_contains = s.contains(pattern);
        let mut encrypted_s = client_key
            .encrypt_str_random_padding(s, string_padding)
            .unwrap();
        let encrypted_pattern = client_key.encrypt_ascii_char(pattern as u8);
        let mut fhe_contains_encrypted = server_key.contains(&encrypted_s, &encrypted_pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_contains_encrypted),
            std_contains as u8
        );
        let mut fhe_contains_clear = server_key.contains(&encrypted_s, &pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_contains_clear),
            std_contains as u8
        );

        encrypted_s = client_key.encrypt_str_padding(s, string_padding).unwrap();
        fhe_contains_encrypted = server_key.contains(&encrypted_s, &encrypted_pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_contains_encrypted),
            std_contains as u8
        );
        let mut fhe_contains_clear = server_key.contains(&encrypted_s, &pattern);
        assert_eq!(
            client_key.decrypt_u8(&fhe_contains_clear),
            std_contains as u8
        );
    }

    pub fn test_contains_char(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: char,
    ) {
        test_contains_char_padding(client_key, server_key, s, pattern, 0);
        test_contains_char_padding(client_key, server_key, s, pattern, 5);
    }

    #[test]
    fn test_contains_char00() {
        test_contains_char(&CLIENT_KEY, &SERVER_KEY, "abc", 'a');
    }

    #[test]
    fn test_contains_char01() {
        test_contains_char(&CLIENT_KEY, &SERVER_KEY, "abc", 'b');
    }

    #[test]
    fn test_contains_char02() {
        test_contains_char(&CLIENT_KEY, &SERVER_KEY, "abc", 'c');
    }

    #[test]
    fn test_contains_char1() {
        test_contains_char(&CLIENT_KEY, &SERVER_KEY, "abc", 'd');
    }

    #[test]
    fn test_contains_char2() {
        test_contains_char(&CLIENT_KEY, &SERVER_KEY, "", 'b');
    }

    #[test]
    fn test_contains_string00() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "a");
    }

    #[test]
    fn test_contains_string01() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "b");
    }

    #[test]
    fn test_contains_string02() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "c");
    }

    #[test]
    fn test_contains_string10() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "ab");
    }

    #[test]
    fn test_contains_string11() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "bc");
    }

    #[test]
    fn test_contains_string2() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "abc");
    }

    #[test]
    fn test_contains_string3() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "abcd");
    }

    #[test]
    fn test_contains_string4() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "d");
    }

    #[test]
    fn test_contains_string5() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "dzzzs");
    }

    #[test]
    fn test_contains_string6() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "abc", "");
    }

    #[test]
    fn test_contains_string7() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "", "abc");
    }

    #[test]
    fn test_contains_string8() {
        test_contains_string(&CLIENT_KEY, &SERVER_KEY, "", "");
    }
}
