use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString};
use crate::server_key::StringServerKey;
use tfhe::integer::BooleanBlock;

#[derive(Debug, PartialEq)]
pub enum FheBool {
    Clear(bool),
    Encrypted(BooleanBlock),
}

impl StringServerKey {
    pub fn len<'a>(&self, s: &'a FheString) -> &'a FheStrLength {
        s.len()
    }
    pub fn is_empty(&self, s: &FheString) -> FheBool {
        match &s.len() {
            FheStrLength::Clear(0) => FheBool::Clear(true),
            FheStrLength::Clear(_) => FheBool::Clear(false),
            FheStrLength::Encrypted(length) => {
                FheBool::Encrypted(self.integer_key.scalar_eq_parallelized(length, 0))
            }
        }
    }

    pub fn is_empty_encrypted(&self, s: &FheString) -> BooleanBlock {
        match &s.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.scalar_eq_parallelized(encrypted_length, 0)
            }
            ClearOrEncrypted::Clear(0) => self.create_true(),
            _ => self.create_false(),
        }
    }
    pub fn is_not_empty_encrypted(&self, s: &FheString) -> BooleanBlock {
        match &s.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.scalar_ne_parallelized(encrypted_length, 0)
            }
            ClearOrEncrypted::Clear(0) => self.create_false(),
            _ => self.create_true(),
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
    use tfhe::integer::BooleanBlock;

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
        let result: BooleanBlock = match SERVER_KEY.is_empty(&encrypted_str) {
            FheBool::Encrypted(encrypted_res) => encrypted_res,
            _ => {
                panic!();
            }
        };
        let clear_result = CLIENT_KEY.decrypt_integer(&SERVER_KEY.bool_to_radix(&result));
        assert_eq!(clear_result, 1);
    }
}
