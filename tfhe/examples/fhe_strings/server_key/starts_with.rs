use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::FhePattern;
use crate::server_key::StringServerKey;
use tfhe::integer::{RadixCiphertext, BooleanBlock};

impl StringServerKey {
    /// Checks if pattern is a prefix of s. Returns an encrypted value of 1 for true, 0 for false.
    pub fn starts_with(&self, s: &FheString, pattern: &impl FhePattern) -> BooleanBlock {
        pattern.is_prefix_of_string(self, s)
    }

    /// Checks if s encrypts a string which has the string encrypted by prefix as a prefix. The
    /// function assumes that both s and prefix do not have initial padding zeros. Returns an
    /// encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn starts_with_encrypted_no_init_padding(
        &self,
        s: &FheString,
        prefix: &FheString,
    ) -> BooleanBlock {
        // First the overlapping contents are compared.
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.content.len(), prefix.content.len()) {
            self.integer_key.boolean_bitand_assign(
                &mut result,
                &match prefix.padding {
                    // Padding is either None or Final.
                    Padding::None => self.compare_char(
                        &s.content[n],
                        &prefix.content[n],
                        std::cmp::Ordering::Equal,
                    ),
                    _ => self.integer_key.boolean_bitor(
                        &self.compare_char(
                            &s.content[n],
                            &prefix.content[n],
                            std::cmp::Ordering::Equal,
                        ),
                        &self
                            .integer_key
                            .scalar_eq_parallelized(&prefix.content[n].0, 0),
                    ),
                },
            )
        }

        // If prefix content size is greater than s content size, check if the extra characters are
        // padding zeros.
        if prefix.content.len() > s.content.len() {
            return self.integer_key.boolean_bitand(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&prefix.content[s.content.len()].0, 0),
            );
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
