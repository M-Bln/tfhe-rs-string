use crate::ciphertext::{FheStrLength, FheString};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

#[derive(Debug, PartialEq)]
pub enum FheBool {
    Clear(bool),
    Crypted(RadixCiphertext),
}

impl StringServerKey {
    pub fn is_empty(&self, s: &FheString) -> FheBool {
        match &s.length {
            FheStrLength::Clear(0) => FheBool::Clear(true),
            FheStrLength::Clear(_) => FheBool::Clear(false),
            FheStrLength::Crypted(length) => {
                FheBool::Crypted(self.integer_key.scalar_eq_parallelized(&length, 0))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{encrypt_str, gen_keys};
    use crate::server_key::is_empty::FheBool;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, StringServerKey) = gen_keys();
    }

    #[test]
    fn test_is_not_empty_clear() {
        let encrypted_str = encrypt_str(&KEYS.0, "no").unwrap();
        assert_eq!(KEYS.1.is_empty(&encrypted_str), FheBool::Clear(false));
    }

    #[test]
    fn test_is_empty_clear() {
        let encrypted_str = encrypt_str(&KEYS.0, "").unwrap();
        assert_eq!(KEYS.1.is_empty(&encrypted_str), FheBool::Clear(true));
    }
}
