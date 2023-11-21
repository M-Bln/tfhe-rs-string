use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn nth_clear(&self, s: &FheString, n: usize) -> FheAsciiChar {
        match s.padding {
            Padding::None | Padding::Final if n < s.content.len() => s.content[n].clone(),
            _ if n >= s.content.len() => FheAsciiChar(self.create_zero()),
            _ => self.nth_clear_with_padding(s, n),
        }
    }

    pub fn nth_encrypted(&self, s: &FheString, n: &RadixCiphertext) -> FheAsciiChar {
        match s.padding {
            Padding::None | Padding::Final => self.nth_encrypted_no_init_padding(s, n),
            _ => self.nth_encrypted_with_padding(s, n),
        }
    }

    pub fn substring_clear(&self, s: &FheString, start: usize, end: usize) -> FheString {
        match s.padding {
            Padding::None | Padding::Final => self.substring_clear_no_init_padding(s, start, end),
            _ => self.substring_clear_no_init_padding(&self.remove_initial_padding(s), start, end),
        }
    }

    pub fn nth_clear_with_padding(&self, s: &FheString, n: usize) -> FheAsciiChar {
        let mut current_index: RadixCiphertext = self.create_n(u8::MAX);
        let mut result = self.create_zero();
        for c in &s.content {
            let current_char_non_null: RadixCiphertext =
                self.integer_key.scalar_ne_parallelized(&c.0, 0);
            self.integer_key
                .add_assign_parallelized(&mut current_index, &current_char_non_null);
            let right_index = self
                .integer_key
                .scalar_eq_parallelized(&current_index, n as u64);
            result = self
                .integer_key
                .cmux_parallelized(&right_index, &c.0, &result)
        }
        FheAsciiChar(result)
    }

    pub fn nth_encrypted_with_padding(
        &self,
        s: &FheString,
        encrypted_n: &RadixCiphertext,
    ) -> FheAsciiChar {
        let mut current_index: RadixCiphertext = self.create_n(u8::MAX);
        let mut result = self.create_zero();
        for c in &s.content {
            let current_char_non_null: RadixCiphertext =
                self.integer_key.scalar_ne_parallelized(&c.0, 0);
            self.integer_key
                .add_assign_parallelized(&mut current_index, &current_char_non_null);
            let right_index = self
                .integer_key
                .eq_parallelized(&current_index, encrypted_n);
            result = self
                .integer_key
                .cmux_parallelized(&right_index, &c.0, &result)
        }
        FheAsciiChar(result)
    }

    pub fn nth_encrypted_no_init_padding(
        &self,
        s: &FheString,
        encrypted_n: &RadixCiphertext,
    ) -> FheAsciiChar {
        let mut result = self.create_zero();
        for i in 0..s.content.len() {
            let right_index = self
                .integer_key
                .scalar_eq_parallelized(encrypted_n, i as u64);
            result = self
                .integer_key
                .cmux_parallelized(&right_index, &s.content[i].0, &result)
        }
        FheAsciiChar(result)
    }

    pub fn substring_clear_no_init_padding(
        &self,
        s: &FheString,
        start: usize,
        end: usize,
    ) -> FheString {
        let mut content: Vec<FheAsciiChar> = Vec::with_capacity(end - start);
        content.extend_from_slice(&s.content[start..end]);
        let padding = match s.padding {
            Padding::None => Padding::None,
            _ => Padding::Final,
        };
        let length = self.length_of_slice(&s.length, start, end);
        FheString {
            content: content,
            padding: padding,
            length: length,
        }
    }

    pub fn length_of_slice(
        &self,
        initial_length: &FheStrLength,
        start: usize,
        end: usize,
    ) -> FheStrLength {
        match initial_length {
            ClearOrEncrypted::Clear(len) if start >= *len => ClearOrEncrypted::Clear(0),
            ClearOrEncrypted::Clear(len) => {
                ClearOrEncrypted::Clear(std::cmp::min(*len, end) - start)
            }
            ClearOrEncrypted::Encrypted(len) => {
                self.length_of_slice_from_encrypted_length(len, start, end)
            }
        }
    }

    pub fn length_of_slice_from_encrypted_length(
        &self,
        initial_encrypted_length: &RadixCiphertext,
        start: usize,
        end: usize,
    ) -> FheStrLength {
        let new_start = self
            .integer_key
            .scalar_min_parallelized(initial_encrypted_length, start as u64);
        let new_end = self
            .integer_key
            .scalar_min_parallelized(initial_encrypted_length, end as u64);
        ClearOrEncrypted::Encrypted(self.integer_key.sub_parallelized(&new_start, &new_end))
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn test_nth_clear() {
        let encrypted_str0 = CLIENT_KEY.encrypt_str_padding("ade", 2).unwrap();
        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);
        let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 1);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 100);

        let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 2);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 97);

        let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 0);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 101);

        let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 3);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 0);
    }

    #[test]
    fn test_nth_encrypted() {
        let encrypted_str = CLIENT_KEY.encrypt_str_padding("ade", 2).unwrap();
        //        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);

        let mut encrypted_char =
            SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(1).0);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 100);

        let mut encrypted_char =
            SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(2).0);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 101);

        let mut encrypted_char =
            SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(0).0);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 97);

        let mut encrypted_char =
            SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(3).0);
        assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 0);
    }

    #[test]
    fn test_substring_clear() {
        let encrypted_str = CLIENT_KEY.encrypt_str_padding("adef", 2).unwrap();
        //        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);

        let encrypted_substr = SERVER_KEY.substring_clear(&encrypted_str, 1, 5);

        assert_eq!(CLIENT_KEY.decrypt_string(&encrypted_substr).unwrap(), "def");
    }
}
