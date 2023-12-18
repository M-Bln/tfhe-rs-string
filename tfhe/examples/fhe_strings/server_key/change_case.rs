use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::StringServerKey;

pub const UP_LOW_DISTANCE: u8 = 32;

// Implement functions to change case of encrypted characters and string.
impl StringServerKey {
    /// Returns a encrypted string encoding the same as c in uppercase.
    /// # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aB.").unwrap();
    /// let encrypted_str_upper = server_key.to_uppercase(&encrypted_str);
    /// let decrypted_str_upper = client_key.decrypt_string(&encrypted_str_upper).unwrap();
    /// assert_eq!(&decrypted_str_upper, "AB.");
    /// ```
    pub fn to_uppercase(&self, c: &FheString) -> FheString {
        FheString {
            content: c
                .content
                .iter()
                .map(|c| self.to_uppercase_char(c))
                .collect(),
            padding: c.padding,
            length: c.length.clone(),
        }
    }

    /// Returns a encrypted string encoding the same as c in lowercase.
    /// # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str_random_padding("BCD", 0).unwrap();
    /// let encrypted_str_lower = server_key.to_lowercase(&encrypted_str);
    /// let decrypted_str_lower = client_key.decrypt_string(&encrypted_str_lower).unwrap();
    /// assert_eq!(&decrypted_str_lower, "bcd");
    /// ```
    pub fn to_lowercase(&self, c: &FheString) -> FheString {
        FheString {
            content: c
                .content
                .iter()
                .map(|c| self.to_lowercase_char(c))
                .collect(),
            padding: c.padding,
            length: c.length.clone(),
        }
    }

    /// Returns a encrypted character encoding the same as c in uppercase.
    pub fn to_uppercase_char(&self, c: &FheAsciiChar) -> FheAsciiChar {
        let change_case = &self.integer_key.boolean_bitand(
            &self.integer_key.scalar_gt_parallelized(&c.0, 96),
            &self.integer_key.scalar_lt_parallelized(&c.0, 123),
        );
        FheAsciiChar(
            self.integer_key.sub_parallelized(
                &c.0,
                &self
                    .integer_key
                    .scalar_mul_parallelized(&self.bool_to_radix(change_case), UP_LOW_DISTANCE),
            ),
        )
    }

    /// Returns a encrypted character encoding the same as c in lowercase.
    pub fn to_lowercase_char(&self, c: &FheAsciiChar) -> FheAsciiChar {
        let change_case = &self.integer_key.boolean_bitand(
            &self.integer_key.scalar_gt_parallelized(&c.0, 64),
            &self.integer_key.scalar_lt_parallelized(&c.0, 91),
        );
        FheAsciiChar(
            self.integer_key.add_parallelized(
                &c.0,
                &self
                    .integer_key
                    .scalar_mul_parallelized(&self.bool_to_radix(change_case), UP_LOW_DISTANCE),
            ),
        )
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

    #[test]
    fn test_to_upper_fhe() {
        let encrypted_str = CLIENT_KEY.encrypt_str("aB.").unwrap();
        let encrypted_str_upper = SERVER_KEY.to_uppercase(&encrypted_str);
        let decrypted_str_upper = CLIENT_KEY.decrypt_string(&encrypted_str_upper).unwrap();
        assert_eq!(&decrypted_str_upper, "AB.");
    }

    #[test]
    fn test_to_lower_fhe() {
        let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("BCD", 0).unwrap();
        let encrypted_str_lower = SERVER_KEY.to_lowercase(&encrypted_str);
        let decrypted_str_lower = CLIENT_KEY.decrypt_string(&encrypted_str_lower).unwrap();
        assert_eq!(&decrypted_str_lower, "bcd");
    }
}
