use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub trait FhePattern {
    fn is_prefix_of(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext;
    fn padding_required_for_is_prefix(&self) -> Padding;
    fn fhe_length(&self) -> FheStrLength;
    fn is_contained_in(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        let mut result = server_key.create_zero();
        for i in 0..haystack.len() {
            server_key.integer_key.bitor_assign_parallelized(
                &mut result,
                &self.is_prefix_of(server_key, &haystack[i..]),
            );
        }
        return result;
    }
}

impl FhePattern for char {
    fn is_prefix_of(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        if haystack.len() == 0 {
            return server_key.create_zero();
        }
        server_key.eq_clear_char(&haystack[0], *self as u8)
    }
    fn fhe_length(&self) -> FheStrLength {
        FheStrLength::Clear(1)
    }
    fn padding_required_for_is_prefix(&self) -> Padding {
        Padding::Final
    }
}

impl FhePattern for FheAsciiChar {
    fn is_prefix_of(
        &self,
        server_key: &StringServerKey,
        haystack: &[FheAsciiChar],
    ) -> RadixCiphertext {
        if haystack.len() == 0 {
            return server_key.create_zero();
        }
        server_key.eq_char(&haystack[0], self)
    }
    fn fhe_length(&self) -> FheStrLength {
        FheStrLength::Clear(1)
    }
    fn padding_required_for_is_prefix(&self) -> Padding {
        Padding::Final
    }
}

impl FhePattern for &str {
    fn is_prefix_of(
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
    fn fhe_length(&self) -> FheStrLength {
        FheStrLength::Clear(self.len())
    }
    fn padding_required_for_is_prefix(&self) -> Padding {
        Padding::Final
    }
}

impl StringServerKey {
    fn starts_with(&self, s: &FheString, pattern: &impl FhePattern) -> RadixCiphertext {
        match &(s.len(), pattern.fhe_length()) {
            (FheStrLength::Clear(s_length), FheStrLength::Clear(pattern_length))
                if s_length < pattern_length =>
            {
                return self.create_zero()
            }
            (_, FheStrLength::Clear(pattern_length)) if s.content.len() < *pattern_length => {
                return self.create_zero()
            }
            _ => (),
        }
        if s.padding.le(&pattern.padding_required_for_is_prefix()) {
            pattern.is_prefix_of(self, &s.content)
        } else {
            pattern.is_prefix_of(self, &self.remove_initial_padding(&s).content)
        }
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

    #[test]
    fn test_starts_with_clear_char() {
        let s = CLIENT_KEY.encrypt_str("abc").unwrap();
        let result = SERVER_KEY.starts_with(&s, &'b');
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
        let result2 = SERVER_KEY.starts_with(&s, &'a');
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    }

    #[test]
    fn test_contains_clear_char() {
        let s = CLIENT_KEY.encrypt_str_random_padding("abc", 2).unwrap();
        let result = SERVER_KEY.contains(&s, &'d');
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
        let result2 = SERVER_KEY.contains(&s, &'b');
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    }

    #[test]
    fn test_starts_with_encrypted_char() {
        let s = CLIENT_KEY.encrypt_str("abc").unwrap();
        let encrypted_char = CLIENT_KEY.encrypt_ascii_char('b' as u8);
        let result = SERVER_KEY.starts_with(&s, &encrypted_char);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
        let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char('a' as u8);
        let result2 = SERVER_KEY.starts_with(&s, &encrypted_char2);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    }

    #[test]
    fn test_contains_encrypted_char() {
        let s = CLIENT_KEY.encrypt_str_random_padding("abc", 2).unwrap();
        let encrypted_char = CLIENT_KEY.encrypt_ascii_char('d' as u8);
        let result = SERVER_KEY.contains(&s, &encrypted_char);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result), 0);
        let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char('a' as u8);
        let result2 = SERVER_KEY.contains(&s, &encrypted_char2);
        assert_eq!(CLIENT_KEY.decrypt_u8(&result2), 1);
    }
}
