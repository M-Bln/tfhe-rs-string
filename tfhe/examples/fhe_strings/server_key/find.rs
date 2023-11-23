use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn find_char(
        &self,
        s: &FheString,
        encrypted_char: &FheAsciiChar,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return (zero.clone(), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match: RadixCiphertext = self.eq_char(&s.content[n], &encrypted_char);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn find_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        match pattern.padding {
            Padding::Final | Padding::None => self.find_unpadded_string(&s, &pattern),
            _ => self.find_unpadded_string(&s, &self.remove_initial_padding(pattern)),
        }
    }

    pub fn rfind_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        match pattern.padding {
            Padding::Final | Padding::None => self.rfind_unpadded_string(&s, &pattern),
            _ => self.rfind_unpadded_string(&s, &self.remove_initial_padding(s)),
        }
    }

    pub fn find_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn rfind_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) =
            (self.create_n((s.content.len() - 1) as u8), zero);
        for n in (0..s.content.len()).rev() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
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
    fn test_find_char() {
        let encrypted_str = CLIENT_KEY.encrypt_str("cdf").unwrap();
        let encrypted_char = CLIENT_KEY.encrypt_ascii_char(102);
        let encrypted_char2 = CLIENT_KEY.encrypt_ascii_char(105);
        let result = SERVER_KEY.find_char(&encrypted_str, &encrypted_char);
        let clear_result = (
            CLIENT_KEY.decrypt_u8(&result.0),
            CLIENT_KEY.decrypt_u8(&result.1),
        );
        let result2 = SERVER_KEY.find_char(&encrypted_str, &encrypted_char2);
        let clear_result2 = (
            CLIENT_KEY.decrypt_u8(&result2.0),
            CLIENT_KEY.decrypt_u8(&result2.1),
        );
        assert_eq!(clear_result, (1, 2));
        assert_eq!(clear_result2, (0, 3));
    }

    // #[test]
    // fn test_find_string() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("cdf").unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("df", 1).unwrap();
    //     let encrypted_pattern2 = CLIENT_KEY.encrypt_str("cf").unwrap();
    //     let result = SERVER_KEY.find_string(&encrypted_str, &encrypted_pattern);
    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );
    //     let result2 = SERVER_KEY.find_string(&encrypted_str, &encrypted_pattern2);
    //     let clear_result2 = (
    //         CLIENT_KEY.decrypt_u8(&result2.0),
    //         CLIENT_KEY.decrypt_u8(&result2.1),
    //     );
    //     assert_eq!(clear_result, (1, 1));
    //     assert_eq!(clear_result2, (0, 2));
    // }

    // #[test]
    // fn test_find_string_with_padding() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_padding("cc", 1).unwrap();
    //     //let encrypted_str2 = CLIENT_KEY.encrypt_str_padding("ac", 2).unwrap();
    //     //let encrypted_str3 = SERVER_KEY.reverse_string_content(&encrypted_str);

    //     let encrypted_pattern = CLIENT_KEY.encrypt_str("d").unwrap();

    //     let result = SERVER_KEY.rfind_string(&encrypted_str, &encrypted_pattern);
    //     //        let result2 = SERVER_KEY.find_string(&encrypted_str3, &encrypted_pattern);

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     // let clear_result2 = (
    //     //     CLIENT_KEY.decrypt_u8(&result2.0),
    //     //     CLIENT_KEY.decrypt_u8(&result2.1),
    //     // );

    //     assert_eq!(clear_result, (0, 255));
    //     //assert_eq!(clear_result2, (1, 0));
    // }
}
