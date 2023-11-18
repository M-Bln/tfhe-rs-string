use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn contains_char(&self, s: &FheString, encrypted_char: &FheAsciiChar) -> RadixCiphertext {
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return self.create_zero(),
            _ => (),
        }
        let mut result: RadixCiphertext = self.create_zero();
        for c in s.content.iter() {
            let c_match: RadixCiphertext = self.eq_char(&c, encrypted_char);
            self.integer_key
                .bitor_assign_parallelized(&mut result, &c_match);
        }
        result
    }

    pub fn contains_clear_char(&self, s: &FheString, clear_char: u8) -> RadixCiphertext {
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return self.create_zero(),
            _ => (),
        }
        let mut result: RadixCiphertext = self.create_zero();
        for c in s.content.iter() {
            let c_match: RadixCiphertext = self.eq_clear_char(&c, clear_char);
            self.integer_key
                .bitor_assign_parallelized(&mut result, &c_match);
        }
        result
    }

    pub fn contains_string(&self, s: &FheString, pattern: &FheString) -> RadixCiphertext {
        match pattern.padding {
            Padding::Final | Padding::None => self.contains_unpadded_string(&s, &pattern),
            _ => self.contains_unpadded_string(&s, &self.remove_initial_padding(s)),
        }
    }

    pub fn contains_clear_string(&self, s: &FheString, pattern: &str) -> RadixCiphertext {
        match (s.content.len(), pattern.len()) {
            (0, 0) => return self.create_true(),
            (0, pattern_lenght) => return self.create_zero(),
            _ => (),
        }
        let mut result = self.create_zero();
        for n in 0..s.content.len() {
            let current_match = self.starts_with_vec_clear(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut result, &current_match);
        }
        result
    }

    pub fn contains_unpadded_string(&self, s: &FheString, pattern: &FheString) -> RadixCiphertext {
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return self.create_true(),
            (0, pattern_lenght) => return self.eq_clear_char(&pattern.content[0], 0),
            _ => (),
        }
        let mut result = self.create_zero();
        for n in 0..s.content.len() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
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
    use crate::ciphertext::gen_keys;
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn test_eq_char() {
        let encrypted_char1 = CLIENT_KEY.encrypt_ascii_char(100);
        let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char(100);
        let encrypted_char3 = CLIENT_KEY.encrypt_ascii_char(101);
        let eq12 = SERVER_KEY.eq_char(&encrypted_char1, &encrypted_char2);
        let eq13 = SERVER_KEY.eq_char(&encrypted_char1, &encrypted_char3);
        assert_eq!(CLIENT_KEY.decrypt_u8(&eq12), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&eq13), 0);
    }

    #[test]
    fn test_contains_char() {
        let encrypted_str = CLIENT_KEY.encrypt_str("cde").unwrap();
        let encrypted_char = CLIENT_KEY.encrypt_ascii_char(100);
        let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char(105);
        let result = SERVER_KEY.contains_char(&encrypted_str, &encrypted_char);
        let result2 = SERVER_KEY.contains_char(&encrypted_str, &encrypted_char2);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 0);
    }

    #[test]
    fn test_contains_clear_char() {
        let encrypted_str = CLIENT_KEY.encrypt_str("cde").unwrap();
        let result = SERVER_KEY.contains_clear_char(&encrypted_str, 100);
        let result2 = SERVER_KEY.contains_clear_char(&encrypted_str, 117);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 0);
    }

    #[test]
    fn test_starts_with_encrypted_vec() {
        let encrypted_vec = CLIENT_KEY.encrypt_str("cde").unwrap().content;
        let encrypted_prefix = CLIENT_KEY.encrypt_str_padding("cd", 2).unwrap();
        let encrypted_prefix2 = CLIENT_KEY.encrypt_str("ce").unwrap();
        let result = SERVER_KEY.starts_with_encrypted_vec(&encrypted_vec, &encrypted_prefix);
        let result2 = SERVER_KEY.starts_with_encrypted_vec(&encrypted_vec, &encrypted_prefix2);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 0);
    }

    #[test]
    fn test_contains_string() {
        let encrypted_str = CLIENT_KEY.encrypt_str("cdea").unwrap();
        let encrypted_str2 = CLIENT_KEY.encrypt_str("").unwrap();
        let encrypted_str3 = CLIENT_KEY.encrypt_str_padding("", 2).unwrap();
        let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("de", 1).unwrap();
        let encrypted_pattern2 = CLIENT_KEY.encrypt_str_padding("df", 1).unwrap();
        let encrypted_pattern3 = CLIENT_KEY.encrypt_str_padding("", 1).unwrap();
        let encrypted_pattern4 = CLIENT_KEY.encrypt_str("").unwrap();
        let result = SERVER_KEY.contains_string(&encrypted_str, &encrypted_pattern);
        let result2 = SERVER_KEY.contains_string(&encrypted_str, &encrypted_pattern2);
        let result3 = SERVER_KEY.contains_string(&encrypted_str, &encrypted_pattern3);
        let result4 = SERVER_KEY.contains_string(&encrypted_str, &encrypted_pattern4);
        let result5 = SERVER_KEY.contains_string(&encrypted_str2, &encrypted_pattern4);
        let result6 = SERVER_KEY.contains_string(&encrypted_str2, &encrypted_pattern3);
        let result7 = SERVER_KEY.contains_string(&encrypted_str3, &encrypted_pattern3);
        let result8 = SERVER_KEY.contains_string(&encrypted_str3, &encrypted_pattern4);
        let result9 = SERVER_KEY.contains_string(&encrypted_str3, &encrypted_pattern);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 0);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result3), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result4), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result5), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result6), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result7), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result8), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result9), 0);
    }

    #[test]
    fn test_contains_clear_string() {
        let encrypted_str = CLIENT_KEY.encrypt_str("cdea").unwrap();
        let encrypted_str2 = CLIENT_KEY.encrypt_str("").unwrap();
        let encrypted_str3 = CLIENT_KEY.encrypt_str_padding("", 2).unwrap();
        let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("de", 1).unwrap();
        let encrypted_pattern2 = CLIENT_KEY.encrypt_str_padding("df", 1).unwrap();
        let encrypted_pattern3 = CLIENT_KEY.encrypt_str_padding("", 1).unwrap();
        let encrypted_pattern4 = CLIENT_KEY.encrypt_str("").unwrap();
        let result = SERVER_KEY.contains_clear_string(&encrypted_str, "de");
        let result2 = SERVER_KEY.contains_clear_string(&encrypted_str, "df");
        let result3 = SERVER_KEY.contains_clear_string(&encrypted_str, "");
        let result6 = SERVER_KEY.contains_clear_string(&encrypted_str2, "");
        let result7 = SERVER_KEY.contains_clear_string(&encrypted_str3, "");
        let result9 = SERVER_KEY.contains_clear_string(&encrypted_str3, "de");
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 0);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result3), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result6), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result7), 1);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result9), 0);
    }
}
