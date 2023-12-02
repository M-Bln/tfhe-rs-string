use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub type ResultFheString = (RadixCiphertext, FheString);

pub struct FheSplit {
    pub parts: Vec<FheString>,
    pub number_parts: RadixCiphertext,
    pub current_index: usize,
}

impl StringServerKey {
    pub fn padding_pair_dispatch<F>(&self, s1: &FheString, s2: &FheString, f: F) -> FheSplit
    where
        F: Fn(&FheString, &FheString) -> FheSplit,
    {
        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => f(s1, s2),
            (Padding::None | Padding::Final, _) => f(s1, &self.remove_initial_padding(s2)),
            (_, Padding::None | Padding::Final) => f(&self.remove_initial_padding(s1), s2),
            _ => f(
                &self.remove_initial_padding(s1),
                &self.remove_initial_padding(s2),
            ),
        }
    }

    pub fn split_encrypted(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        match &pattern.length {
            ClearOrEncrypted::Clear(0) => {
                self.padding_pair_dispatch(s, pattern, |s1, s2| self.split_empty_pattern(s1, s2))
            }
            ClearOrEncrypted::Clear(_) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_encrypted_final_padding(s1, s2)
            }),
            _ => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
        }
    }

    pub fn split_clear_n_encrypted(
        &self,
        n: usize,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        self.padding_pair_dispatch(s, pattern, |s1, s2| {
            self.split_clear_n_encrypted_final_padding_allow_empty_pattern(n, s1, s2)
        })
    }

    pub fn split_empty_pattern(&self, s: &FheString, _empty_pattern: &FheString) -> FheSplit {
        let max_number_parts = s.content.len() + 2;
        let mut parts: Vec<FheString> = Vec::with_capacity(max_number_parts);
        let number_parts: RadixCiphertext = match &s.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_add_parallelized(encrypted_length, 2),
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length + 2) as u8),
        };
        let empty_string = FheString {
            padding: Padding::None,
            length: ClearOrEncrypted::Clear(0),
            content: Vec::new(),
        };
        parts.push(empty_string.clone());
        for c in &s.content {
            let current_char_non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
            parts.push(FheString {
                padding: Padding::Final,
                length: ClearOrEncrypted::Encrypted(current_char_non_null),
                content: vec![c.clone()],
            })
        }
        parts.push(empty_string);
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_encrypted_final_padding(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();

        for n in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found);

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.add_length_to_radix(&end_part, &pattern.length);
        }
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_clear_n_encrypted_final_padding(
        &self,
        n: usize,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let maximum_number_of_parts_or_n = std::cmp::min(maximum_number_of_parts, n);
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();

        for i in 0..maximum_number_of_parts_or_n {
            let (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);
            if i == n - 1 {
                parts.push(self.final_substring_encrypted_final_padding(s, &start_part));
            } else {
                // Increment `number_parts` if the pattern is found.
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &found);
                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                start_part = self.add_length_to_radix(&end_part, &pattern.length);
            }
        }

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_encrypted_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let empty_pattern = self.is_empty_encrypted(&pattern);

        for n in 0..maximum_number_of_parts {
            let found: RadixCiphertext;
            let end_part: RadixCiphertext;
            if n >= 1 {
                // When the patern is empty, the search must start at `start_part` plus 1.
                (found, end_part) = self.find_from_final_padding_allow_empty_pattern(
                    s,
                    pattern,
                    &self
                        .integer_key
                        .add_parallelized(&start_part, &empty_pattern),
                );
            } else {
                (found, end_part) =
                    self.find_from_final_padding_allow_empty_pattern(s, pattern, &start_part);
            }

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found);

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.add_length_to_radix(&end_part, &pattern.length);
        }
        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &empty_pattern,
            &self.add_length_scalar(&s.length, 2),
            &number_parts,
        );
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn add_length_scalar(&self, length: &FheStrLength, n: u64) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length + 2) as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_add_parallelized(encrypted_length, 2),
        }
    }

    pub fn split_clear_n_encrypted_final_padding_allow_empty_pattern(
        &self,
        n: usize,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let maximum_number_of_parts_or_n = std::cmp::min(maximum_number_of_parts, n);

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let empty_pattern = self.is_empty_encrypted(&pattern);

        for i in 0..maximum_number_of_parts_or_n {
            let found: RadixCiphertext;
            let end_part: RadixCiphertext;
            if i >= 1 {
                // When the patern is empty, the search must start at `start_part` plus 1.
                (found, end_part) = self.find_from_final_padding(
                    s,
                    pattern,
                    &self
                        .integer_key
                        .add_parallelized(&start_part, &empty_pattern),
                );
            } else {
                (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);
            }

            if i == n - 1 {
                parts.push(self.final_substring_encrypted_final_padding(s, &start_part));
            } else {
                // Increment `number_parts` if the pattern is found.
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &found);
                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                start_part = self.add_length_to_radix(&end_part, &pattern.length);
            }
        }
        // Count the final empty string when the pattern is empty
        let count_final_empty_string = self.integer_key.bitand_parallelized(
            &empty_pattern,
            &self
                .integer_key
                .scalar_ne_parallelized(&s.content[s.content.len() - 1].0, 0),
        );
        if n >= maximum_number_of_parts {
            // if n >= number_of_par
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &count_final_empty_string);
        }
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn add_length_to_radix(
        &self,
        end_part: &RadixCiphertext,
        pattern_length: &FheStrLength,
    ) -> RadixCiphertext {
        match pattern_length {
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .add_parallelized(end_part, encrypted_length),
            ClearOrEncrypted::Clear(clear_length) => self
                .integer_key
                .scalar_add_parallelized(end_part, *clear_length as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_test, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    pub fn test_split(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
    ) {
        let std_split: Vec<String> = s.split(pattern).map(|s| String::from(s)).collect();
        let encrypted_s = client_key.encrypt_str_random_padding(s, 3).unwrap();
        let encrypted_pattern = client_key.encrypt_str_random_padding(pattern, 3).unwrap();
        let fhe_split = server_key.split_encrypted(&encrypted_s, &encrypted_pattern);
        let clear_len = client_key.decrypt_u8(&fhe_split.number_parts);
        assert_eq!(clear_len, std_split.len() as u8);
        let clear_split: Vec<String> = fhe_split.parts[..(clear_len as usize)]
            .iter()
            .map(|s| client_key.decrypt_string(s).unwrap())
            .collect();
        assert_eq!(clear_split, std_split);
    }

    pub fn test_rsplit(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
    ) {
        let std_rsplit: Vec<String> = s.rsplit(pattern).map(|s| String::from(s)).collect();
        let encrypted_s = client_key.encrypt_str_padding(s, 1).unwrap();
        let encrypted_pattern = client_key.encrypt_str_padding(pattern, 1).unwrap();
        let fhe_rsplit = server_key.rsplit_encrypted(&encrypted_s, &encrypted_pattern);
        let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
        assert_eq!(clear_len, std_rsplit.len() as u8);
        let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(clear_len as usize)]
            .iter()
            .map(|s| client_key.decrypt_string(s).unwrap())
            .collect();
        // let clear_rsplit: Vec<String> = fhe_rsplit.parts[..6].iter().map(|s|
        // client_key.decrypt_string(s).unwrap()).collect();
        assert_eq!(clear_rsplit, std_rsplit);
    }

    // #[test]
    // fn test_test_split() {
    // 	test_split(&CLIENT_KEY, &SERVER_KEY, "acbcbb", "cb");
    // }

    #[test]
    fn test_test_rsplit() {
        test_rsplit(&CLIENT_KEY, &SERVER_KEY, "acb", "c");
    }

    #[test]
    fn test_test_rsplit2() {
        test_rsplit(&CLIENT_KEY, &SERVER_KEY, "acb", "");
    }

    // #[test]
    // fn test_nth_clear() {
    //     let encrypted_str0 = CLIENT_KEY.encrypt_str_random_padding("ade", 0).unwrap();
    //     let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);
    //     let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 1);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 100);

    //     let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 2);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 97);

    //     let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 0);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 101);

    //     let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 3);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 0);
    // }

    // #[test]
    // fn test_nth_encrypted() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ade", 0).unwrap();

    //     let mut encrypted_char =
    //         SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(1).0);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 100);

    //     let mut encrypted_char =
    //         SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(2).0);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 101);

    //     let mut encrypted_char =
    //         SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(0).0);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 97);

    //     let mut encrypted_char =
    //         SERVER_KEY.nth_encrypted(&encrypted_str, &CLIENT_KEY.encrypt_ascii_char(3).0);
    //     assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 0);
    // }

    // #[test]
    // fn test_substring_clear() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ad", 1).unwrap();
    //     let result = SERVER_KEY.substring_clear(&encrypted_str, 1, 3).unwrap();

    //     let encrypted_substr = result.1;
    //     let encrypted_flag = result.0;

    //     assert_eq!(CLIENT_KEY.decrypt_string(&encrypted_substr).unwrap(), "d");
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&encrypted_flag), 0);
    // }

    // #[test]
    // fn test_substring_encrypted() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("adc", 0).unwrap();
    //     let encrypted_start = SERVER_KEY.create_n(1);
    //     let encrypted_end = SERVER_KEY.create_n(2);
    //     let result =
    //         SERVER_KEY.substring_encrypted(&encrypted_str, &encrypted_start, &encrypted_end);

    //     let encrypted_substr = result.1;
    //     let encrypted_flag = result.0;

    //     assert_eq!(CLIENT_KEY.decrypt_string(&encrypted_substr).unwrap(), "d");
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&encrypted_flag), 1);
    // }

    // #[test]
    // fn test_find_from_final_padding() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("a").unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("", 1).unwrap();

    //     let result = SERVER_KEY.find_from_final_padding(
    //         &encrypted_str,
    //         &encrypted_pattern,
    //         &SERVER_KEY.create_n(1),
    //     );

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );
    //     assert_eq!(clear_result, (1, 1));
    // }

    // #[test]
    // fn test_split_encrypted() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("abcab").unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("ab", 1).unwrap();

    //     let result = SERVER_KEY
    //         .split_encrypted_final_padding_allow_empty_pattern(&encrypted_str,
    // &encrypted_pattern);

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    //         CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    //         CLIENT_KEY.decrypt_string(&result.parts[2]).unwrap(),
    //     );

    //     assert_eq!(
    //         clear_result,
    //         (String::from(""), String::from("c"), String::from(""))
    //     );
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 3);
    // }

    //     #[test]
    //     fn test_split_encrypted2() {
    //         let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("a", 3).unwrap();
    //         let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("a", 2).unwrap();

    //         let result = SERVER_KEY
    //             .split_encrypted(&encrypted_str,
    // 			     &encrypted_pattern);
    // 	let clear_result = (
    //             CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    //             CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    // //	    CLIENT_KEY.decrypt_string(&result.parts[2]).unwrap(),
    // //	    CLIENT_KEY.decrypt_string(&result.parts[3]).unwrap(),
    //         );

    //         assert_eq!(clear_result, (String::from(""), String::from("")));
    //         assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 2);
    //     }

    // #[test]
    // fn test_rsplit_empty_pattern() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ab", 1).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("", 0).unwrap();

    //     let result = SERVER_KEY
    //         .rsplit_empty_pattern(&encrypted_str, &encrypted_pattern);
    //     let clear_result = (
    //         CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    //         CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    // 	    CLIENT_KEY.decrypt_string(&result.parts[2]).unwrap(),
    // 	    CLIENT_KEY.decrypt_string(&result.parts[3]).unwrap(),
    //     );

    //     assert_eq!(clear_result, (String::from(""), String::from("b"), String::from("a"),
    // String::from(""),));     assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 4);
    // }

    // #[test]
    // fn test_rsplit_encrypted_initial_padding() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ab", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("a", 0).unwrap();

    //     let result = SERVER_KEY
    //         .rsplit_encrypted_initial_padding(&encrypted_str, &encrypted_pattern);
    //     let clear_result = (
    //         CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    //         CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    //     );

    //     assert_eq!(clear_result, (String::from("b"), String::from("")));
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 2);
    // }

    // #[test]
    // fn test_split_clear_n_encrypted_final_padding() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("a", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_random_padding("", 0).unwrap();

    //     let result = SERVER_KEY
    //         .split_clear_n_encrypted_final_padding_allow_empty_pattern(5, &encrypted_str,
    // &encrypted_pattern);     let clear_result = (
    //         CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    // 	    CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    // 	    CLIENT_KEY.decrypt_string(&result.parts[2]).unwrap(),
    //     );

    //     assert_eq!(clear_result, (String::from(""), String::from("a"), String::from(""),));
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 3);
    // }

    // #[test]
    // fn test_split_clear_n_encrypted_final_padding() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_padding("aaa", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("a", 0).unwrap();

    //     let result = SERVER_KEY.split_clear_n_encrypted(2, &encrypted_str, &encrypted_pattern);
    //     let clear_result = (
    //         CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    //         CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    //     );

    //     assert_eq!(clear_result, (String::from(""), String::from("aa"),));
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 2);
    // }
}
