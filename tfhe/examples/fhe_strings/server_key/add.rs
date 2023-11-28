use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;

impl StringServerKey {
    pub fn add_encrypted(&self, mut s1: FheString, s2: &FheString) -> FheString {
        let result_padding: Padding = match (s1.padding, s2.padding) {
            (Padding::None, Padding::None) => Padding::None,
            (Padding::None, Padding::Final) => Padding::Final,
            (Padding::Initial, Padding::None) => Padding::Initial,
            (Padding::Initial, Padding::Final) => Padding::InitialAndFinal,
            _ => Padding::Anywhere,
        };

        let result_length = self.add_length(&s1.length, &s2.length);
        s1.content.append(&mut s2.content.clone());

        FheString {
            content: s1.content,
            length: result_length,
            padding: result_padding,
        }
    }

    pub fn add_length(&self, l1: &FheStrLength, l2: &FheStrLength) -> FheStrLength {
        match (&l1, &l2) {
            (FheStrLength::Encrypted(encrypted_l1), l2) => self.add_radix_length(l2, encrypted_l1),
            (l1, FheStrLength::Encrypted(encrypted_l2)) => self.add_radix_length(l1, encrypted_l2),
            (FheStrLength::Clear(clear_l1), FheStrLength::Clear(clear_l2)) => {
                FheStrLength::Clear(*clear_l1 + *clear_l2)
            }
        }
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
    fn test_add_encrypted() {
        let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("a", 1).unwrap();
        let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("b", 1).unwrap();
        let add_str1_str2 = SERVER_KEY.add_encrypted(encrypted_str1, &encrypted_str2);
        let decrypted_str = CLIENT_KEY.decrypt_string(&add_str1_str2).unwrap();
        assert_eq!(decrypted_str, "ab");
    }
}
