use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

impl StringServerKey {
    /// Repeats the string s n times, for n a clear integer. It just concatenate the content n
    /// times. Therefore the returned string has padding anywhere as soon as s has some padding. #
    /// Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let s = client_key.encrypt_str_random_padding("ab", 1).unwrap();
    /// let repeated_s = server_key.repeat_clear(&s, 3);
    /// let decrypted_result = client_key.decrypt_string(&repeated_s).unwrap();
    /// assert_eq!(decrypted_result, "ababab");
    /// ```
    pub fn repeat_clear(&self, s: &FheString, n: usize) -> FheString {
        let mut result = FheString {
            content: Vec::with_capacity(n * s.content.len()),
            length: ClearOrEncrypted::Clear(0),
            padding: Padding::None,
        };
        for _ in 0..n {
            result = self.add_encrypted(result, s);
        }
        result
    }

    /// Repeats the string s n times, for n an encrypted integer. A maximum number of repeatition
    /// must be provided as a clear integer n_max. n can be any integer smaller than n_max. This is
    /// necessary as the length of the content vector of the result is known in any case without
    /// decryption. The returned string has padding anywhere as soon as s has some padding. #
    /// Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let s = client_key.encrypt_str_random_padding("a", 1).unwrap();
    /// let encrypted_n = server_key.create_n(2);
    /// let repeated_s = server_key.repeat_encrypted(&s, &encrypted_n, 2);
    /// let decrypted_result = client_key.decrypt_string(&repeated_s).unwrap();
    /// assert_eq!(decrypted_result, "aa");
    /// ```
    pub fn repeat_encrypted(&self, s: &FheString, n: &RadixCiphertext, n_max: usize) -> FheString {
        let zero = self.create_zero();

        let result_padding = match s.padding {
            Padding::None => Padding::None,
            _ => Padding::Anywhere,
        };

        let result_length = self.radix_multiply_length(&s.length, n);
        let mut result_content = Vec::with_capacity(s.content.len() * n_max);

        for i in 0..n_max {
            for c in &s.content {
                let repeat_again: BooleanBlock =
                    self.integer_key.scalar_gt_parallelized(n, i as u64);
                let new_encrypted_char = FheAsciiChar(self.integer_key.cmux_parallelized(
                    &repeat_again,
                    &c.0,
                    &zero,
                ));
                result_content.push(new_encrypted_char);
            }
        }
        FheString {
            padding: result_padding,
            length: result_length,
            content: result_content,
        }
    }

    /// Multiply length by the encrypted integer n.
    pub fn radix_multiply_length(
        &self,
        length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match &length {
            ClearOrEncrypted::Clear(clear_length) => ClearOrEncrypted::Encrypted(
                self.integer_key
                    .scalar_mul_parallelized(n, *clear_length as u64),
            ),
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                ClearOrEncrypted::Encrypted(self.integer_key.mul_parallelized(n, encrypted_length))
            }
        }
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
    fn test_repeat_clear() {
        let s = CLIENT_KEY.encrypt_str_random_padding("ab", 1).unwrap();
        let repeated_s = SERVER_KEY.repeat_clear(&s, 3);
        let decrypted_result = CLIENT_KEY.decrypt_string(&repeated_s).unwrap();
        assert_eq!(decrypted_result, "ababab");
    }

    #[test]
    fn test_repeat_encrypted() {
        let s = CLIENT_KEY.encrypt_str_random_padding("a", 1).unwrap();
        let encrypted_n = SERVER_KEY.create_n(2);
        let repeated_s = SERVER_KEY.repeat_encrypted(&s, &encrypted_n, 2);
        let decrypted_result = CLIENT_KEY.decrypt_string(&repeated_s).unwrap();
        assert_eq!(decrypted_result, "aa");
    }
}
