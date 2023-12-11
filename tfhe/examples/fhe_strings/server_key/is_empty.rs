use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

#[derive(Debug, PartialEq)]
pub enum FheBool {
    Clear(bool),
    Encrypted(RadixCiphertext),
}

impl StringServerKey {
    pub fn is_empty(&self, s: &FheString) -> FheBool {
        match &s.length {
            FheStrLength::Clear(0) => FheBool::Clear(true),
            FheStrLength::Clear(_) => FheBool::Clear(false),
            FheStrLength::Encrypted(length) => {
                FheBool::Encrypted(self.integer_key.scalar_eq_parallelized(&length, 0))
            }
        }
    }

    pub fn is_empty_encrypted(&self, s: &FheString) -> RadixCiphertext {
        match &s.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.scalar_eq_parallelized(encrypted_length, 0)
            }
            ClearOrEncrypted::Clear(0) => self.create_n(1),
            _ => self.create_zero(),
        }
    }
    pub fn is_not_empty_encrypted(&self, s: &FheString) -> RadixCiphertext {
        match &s.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.scalar_ne_parallelized(encrypted_length, 0)
            }
            ClearOrEncrypted::Clear(0) => self.create_zero(),
            _ => self.create_n(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys;
    use crate::client_key::StringClientKey;
    use crate::server_key::is_empty::FheBool;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;
    use tfhe::integer::RadixCiphertext;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn test_is_not_empty_clear() {
        let encrypted_str = CLIENT_KEY.encrypt_str("no").unwrap();
        assert_eq!(SERVER_KEY.is_empty(&encrypted_str), FheBool::Clear(false));
    }

    #[test]
    fn test_is_empty_clear() {
        let encrypted_str = CLIENT_KEY.encrypt_str_padding("", 1).unwrap();
        let result: RadixCiphertext = match SERVER_KEY.is_empty(&encrypted_str) {
            FheBool::Encrypted(encrypted_res) => encrypted_res,
            _ => {
                panic!();
            }
        };
        let clear_result = CLIENT_KEY.decrypt_u8(&result);
        assert_eq!(clear_result, 1);
    }
}
