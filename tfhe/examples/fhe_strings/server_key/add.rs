use crate::ciphertext::{FheAsciiChar, FheString, Padding};
use crate::pattern::FhePattern;
use crate::server_key::StringServerKey;

impl StringServerKey {
    /// Concatenates the pattern to the end of the encrypted string s1. It consumes s1 and returns a
    /// `FheString`.
    /// # Examples
    ///
    /// ```
    /// let x = 5;
    /// assert_eq!(x, 5);
    /// ```
    pub fn add(&self, s1: FheString, pattern: &impl FhePattern) -> FheString {
        pattern.push_to(self, s1)
    }

    /// Concatenates an encrypted string `pattern` to the end of the encrypted string s1. It
    /// consumes s1 and returns a `FheString`.
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

    /// Concatenates an clear string `pattern` to the end of the encrypted string s1. It consumes s1
    /// and returns a `FheString`.
    pub fn add_clear(&self, mut s1: FheString, s2: &str) -> FheString {
        if s2.is_empty() {
            return s1;
        }
        let result_padding: Padding = match s1.padding {
            Padding::None => Padding::None,
            Padding::Initial => Padding::Initial,
            _ => Padding::Anywhere,
        };

        let result_length = self.add_scalar_to_length(&s1.length, s2.len());
        s1.content
            .append(&mut self.server_encrypt_str(s2).unwrap().content.clone());

        FheString {
            content: s1.content,
            length: result_length,
            padding: result_padding,
        }
    }

    /// Concatenates a clear character `c` to the end of the encrypted string s1. It consumes s1 and
    /// returns a `FheString`.
    pub fn add_clear_char(&self, s1: FheString, c: char) -> FheString {
        self.add_encrypted_char(s1, &self.server_encrypt_ascii_char(c))
    }

    /// Concatenates an encrypted character `c` to the end of the encrypted string s1. It consumes
    /// s1 and returns a `FheString`.
    pub fn add_encrypted_char(&self, mut s1: FheString, c: &FheAsciiChar) -> FheString {
        let result_padding: Padding = match s1.padding {
            Padding::None => Padding::None,
            Padding::Initial => Padding::Initial,
            _ => Padding::Anywhere,
        };

        let result_length = self.add_scalar_to_length(&s1.length, 1);
        s1.content.push(c.clone());

        FheString {
            content: s1.content,
            length: result_length,
            padding: result_padding,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys_test, FheStrLength};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_fhe_add_char_pattern, test_fhe_add_string_pattern};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    test_fhe_add_string_pattern!(add, "", "");
    test_fhe_add_string_pattern!(add, "ab", "");
    test_fhe_add_string_pattern!(add, "aezfb", "cdfzefzef");
    test_fhe_add_string_pattern!(add, "", "cd");

    test_fhe_add_char_pattern!(add, "", 'a');
    test_fhe_add_char_pattern!(add, "ab", 'a');
    test_fhe_add_char_pattern!(add, "aezfb", 'a');
    // #[test]
    // fn test_add_encrypted() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("ab", 0).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("bc", 0).unwrap();
    //     let add_str1_str2 = SERVER_KEY.add_encrypted(encrypted_str1, &encrypted_str2);
    //     let decrypted_str = CLIENT_KEY.decrypt_string(&add_str1_str2).unwrap();
    //     assert_eq!(decrypted_str, "abbc");
    // }

    // #[test]
    // fn test_add_encrypted() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("ab", 0).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("bc", 0).unwrap();
    //     let add_str1_str2 = SERVER_KEY.add_encrypted(encrypted_str1, &encrypted_str2);
    //     let decrypted_str = CLIENT_KEY.decrypt_string(&add_str1_str2).unwrap();
    //     assert_eq!(decrypted_str, "abbc");
    // }
}
