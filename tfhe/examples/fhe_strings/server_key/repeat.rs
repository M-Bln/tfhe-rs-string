use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;

impl StringServerKey {
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
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, FheAsciiChar};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

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
}
