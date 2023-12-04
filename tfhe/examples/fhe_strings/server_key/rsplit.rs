use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn rpadding_pair_dispatch<F>(&self, s1: &FheString, s2: &FheString, f: F) -> FheSplit
    where
        F: Fn(&FheString, &FheString) -> FheSplit,
    {
        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Initial, Padding::None | Padding::Initial) => f(s1, s2),
            (Padding::None | Padding::Initial, _) => f(s1, &self.remove_final_padding(s2)),
            (_, Padding::None | Padding::Initial) => f(&self.remove_final_padding(s1), s2),
            _ => f(
                &self.remove_final_padding(s1),
                &self.remove_final_padding(s2),
            ),
        }
    }

    pub fn rsplit_encrypted(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        match &pattern.length {
            ClearOrEncrypted::Clear(0) => {
                self.rpadding_pair_dispatch(s, pattern, |s1, s2| self.rsplit_empty_pattern(s1, s2))
            }
            ClearOrEncrypted::Clear(_) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
            _ => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
        }
    }

    pub fn rsplit_clear_n_encrypted(
        &self,
        n: usize,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        self.padding_pair_dispatch(s, pattern, |s1, s2| {
            self.rsplit_clear_n_encrypted_final_padding_allow_empty_pattern(n, s1, s2)
        })
    }

    pub fn rsplit_clear_n_encrypted_final_padding_allow_empty_pattern(
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
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts_or_n);
        let zero = self.create_zero();
        let mut number_parts = match n {
            0 => self.create_zero(),
            _ => self.create_n(1), // The result has at least 1 part as long as n > 0.
        };

        let mut found = zero.clone();

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_zero(), &s.length);
        let empty_pattern = self.is_empty_encrypted(&pattern);

        for i in 0..maximum_number_of_parts_or_n {
            let start_pattern: RadixCiphertext;
            if i >= 1 {
                (found, start_pattern) = self.rfind_from_final_padding_allow_empty_pattern(
                    s,
                    pattern,
                    &self.integer_key.sub_parallelized(
                        &self.sub_length_to_radix(&end_part, &pattern.length),
                        &empty_pattern,
                    ),
                );
            } else {
                (found, start_pattern) =
                    self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);
            }

            if i >= n - 1 {
                parts.push(self.substring_encrypted_final_padding(
                    s,
                    &self.create_zero(),
                    &end_part,
                ))
            } else {
                // Increment `number_parts` if the pattern is found.
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &found);

                let start_part = self.integer_key.cmux_parallelized(
                    &found,
                    &self.add_length_to_radix(&start_pattern, &pattern.length),
                    &zero,
                );

                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                end_part = self
                    .integer_key
                    .cmux_parallelized(&found, &start_pattern, &zero);
            }
        }

        let number_parts_rsplit_empty_pattern = &self.add_length_scalar(&s.length, 2);
        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &self.integer_key.bitand_parallelized(
                &empty_pattern,
                &self
                    .integer_key
                    .scalar_le_parallelized(&number_parts_rsplit_empty_pattern, n as u64),
            ),
            &number_parts_rsplit_empty_pattern,
            &number_parts,
        );

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_empty_pattern(&self, s: &FheString, _empty_pattern: &FheString) -> FheSplit {
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
        for c in s.content.iter().rev() {
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

    // pub fn rsplit_empty_pattern(&self, s: &FheString, _empty_pattern: &FheString) -> FheSplit {
    //     let max_number_parts = s.content.len() + 2;
    //     let mut parts: Vec<FheString> = Vec::with_capacity(max_number_parts);
    //     let number_parts: RadixCiphertext = match &s.length {
    //         ClearOrEncrypted::Encrypted(encrypted_length) => self
    //             .integer_key
    //             .scalar_add_parallelized(encrypted_length, 2),
    //         ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length + 2) as u8),
    //     };
    //     let empty_string = FheString {
    //         padding: Padding::None,
    //         length: ClearOrEncrypted::Clear(0),
    //         content: Vec::new(),
    //     };
    //     parts.push(empty_string.clone());
    // 	for n in (0..s.content.len()).rev(){
    //         let current_char_non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
    //         parts.push(FheString {
    //             padding: Padding::Final,
    //             length: ClearOrEncrypted::Encrypted(current_char_non_null),
    //             content: vec![c.clone()],
    //         })
    //     }
    //     for c in s.content.iter().rev() {
    //         let current_char_non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
    //         parts.push(FheString {
    //             padding: Padding::Final,
    //             length: ClearOrEncrypted::Encrypted(current_char_non_null),
    //             content: vec![c.clone()],
    //         })
    //     }
    //     parts.push(empty_string);
    //     FheSplit {
    //         parts: parts,
    //         number_parts: number_parts,
    //         current_index: 0,
    //     }
    // }

    // pub fn rsplit_encrypted_final_padding(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    // ) -> FheSplit {
    //     // Compute the maximum number of parts of the result.
    //     let maximum_number_of_parts = match &s.length {
    //         ClearOrEncrypted::Clear(length) => *length + 2,
    //         _ => s.content.len() + 2,
    //     };
    //     let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
    //     let zero = self.create_zero();
    //     let mut number_parts = self.create_n(1); // The result has at least 1 part.

    //     // `start_part` holds the index of the beginning of the current part.
    //     let mut start_part = self.create_n(maximum_number_of_parts as u8);
    //     let empty_pattern = self.is_empty_encrypted(&pattern);

    //     for n in (0..maximum_number_of_parts).rev() {
    //         let found: RadixCiphertext;
    //         let end_part: RadixCiphertext;
    //         if n >= 1 {
    //             // When the patern is empty, the search must start at `start_part` minus 1.
    //             (found, end_part) = self.rfind_from_final_padding_allow_empty_pattern(
    //                 s,
    //                 pattern,
    //                 &self
    //                     .integer_key
    //                     .sub_parallelized(&start_part, &empty_pattern),
    //             );
    //         } else {
    //             (found, end_part) =
    //                 self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &start_part);
    //         }

    //         // Increment `number_parts` if the pattern is found.
    //         self.integer_key
    //             .add_assign_parallelized(&mut number_parts, &found);

    //         parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
    //         start_part = self.add_length_to_radix(&end_part, &pattern.length);
    //     }
    //     // Count the final empty string when the pattern is empty
    //     self.integer_key
    //         .add_assign_parallelized(&mut number_parts, &empty_pattern);
    //     FheSplit {
    //         parts: parts,
    //         number_parts: number_parts,
    //         current_index: 0,
    //     }
    // }

    // pub fn rsplit_encrypted_final_padding_allow_empty_pattern(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    // ) -> FheSplit {
    //     // Compute the maximum number of parts of the result.
    //     let maximum_number_of_parts = match &s.length {
    //         ClearOrEncrypted::Clear(length) => *length + 2,
    //         _ => s.content.len() + 2,
    //     };
    //     let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
    //     let zero = self.create_zero();
    //     let mut number_parts = self.create_n(1); // The result has at least 1 part.

    //     // `start_part` holds the index of the beginning of the current part.
    //     let mut start_part = self.create_n(maximum_number_of_parts as u8);
    //     let empty_pattern = self.is_empty_encrypted(&pattern);

    //     for n in (0..maximum_number_of_parts).rev() {
    //         let found: RadixCiphertext;
    //         let end_part: RadixCiphertext;
    //         if n >= 1 {
    //             // When the patern is empty, the search must start at `start_part` minus 1.
    //             (found, end_part) = self.rfind_from_final_padding_allow_empty_pattern(
    //                 s,
    //                 pattern,
    //                 &self
    //                     .integer_key
    //                     .sub_parallelized(&start_part, &empty_pattern),
    //             );
    //         } else {
    //             (found, end_part) =
    //                 self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &start_part);
    //         }

    //         // Increment `number_parts` if the pattern is found.
    //         self.integer_key
    //             .add_assign_parallelized(&mut number_parts, &found);

    //         parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
    //         start_part = self.add_length_to_radix(&end_part, &pattern.length);
    //     }
    //     // Count the final empty string when the pattern is empty
    //     self.integer_key
    //         .add_assign_parallelized(&mut number_parts, &empty_pattern);
    //     FheSplit {
    //         parts: parts,
    //         number_parts: number_parts,
    //         current_index: 0,
    //     }
    // }

    pub fn rsplit_encrypted_final_padding(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.initial_index_rfind(&s.length);

        for n in (0..maximum_number_of_parts).rev() {
            let (found, start_pattern) =
                self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found);

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self.add_length_to_radix(&start_pattern, &pattern.length),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = start_pattern;
        }
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_encrypted_final_padding_allow_empty_pattern(
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
        let mut found = zero.clone();

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_zero(), &s.length);
        let empty_pattern = self.is_empty_encrypted(&pattern);

        for n in (0..maximum_number_of_parts).rev() {
            let start_pattern: RadixCiphertext;
            if n < maximum_number_of_parts - 1 {
                (found, start_pattern) = self.rfind_from_final_padding_allow_empty_pattern(
                    s,
                    pattern,
                    &self.integer_key.sub_parallelized(
                        &self.sub_length_to_radix(&end_part, &pattern.length),
                        &empty_pattern,
                    ),
                );
            } else {
                (found, start_pattern) =
                    self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);
            }

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found);

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self.add_length_to_radix(&start_pattern, &pattern.length),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
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

    // pub fn rsplit_encrypted_final_padding_allow_empty_pattern(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    // ) -> FheSplit {
    //     // Compute the maximum number of parts of the result.
    //     let maximum_number_of_parts = match &s.length {
    //         ClearOrEncrypted::Clear(length) => *length + 2,
    //         _ => s.content.len() + 2,
    //     };
    //     let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
    //     let zero = self.create_zero();
    //     let mut number_parts = self.create_n(1); // The result has at least 1 part.
    //     let empty_pattern = self.is_empty_encrypted(&pattern);

    //     // `end_part` holds the index of the end of the current part.
    //     let mut end_part = self.initial_index_rfind(&s.length);

    //     for n in (0..maximum_number_of_parts).rev() {
    //         let found: RadixCiphertext;
    //         let start_pattern: RadixCiphertext;
    //         if n >= 1 {
    //             // When the patern is empty, the search must start at `end_part` minus 1.
    //             (found, start_pattern) = self.rfind_from_final_padding_allow_empty_pattern(
    //                 s,
    //                 pattern,
    //                 &self.integer_key.sub_parallelized(&end_part, &empty_pattern),
    //             );
    //         } else {
    //             (found, start_pattern) =
    //                 self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);
    //         }

    //         // Increment `number_parts` if the pattern is found.
    //         self.integer_key
    //             .add_assign_parallelized(&mut number_parts, &found);

    //         let start_part = self.integer_key.cmux_parallelized(
    //             &found,
    //             &self.add_length_to_radix(&start_pattern, &pattern.length),
    //             &zero,
    //         );

    //         parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
    //         end_part = start_pattern;
    //     }
    //     FheSplit {
    //         parts: parts,
    //         number_parts: number_parts,
    //         current_index: 0,
    //     }
    // }
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

    pub fn test_rsplit(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        s: &str,
        pattern: &str,
    ) {
        let std_rsplit: Vec<String> = s.rsplit(pattern).map(|s| String::from(s)).collect();
        let encrypted_s = client_key.encrypt_str_padding(s, 2).unwrap();
        let encrypted_pattern = client_key.encrypt_str_padding(pattern, 2).unwrap();
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

    pub fn test_rsplit_clear_n(
        client_key: &StringClientKey,
        server_key: &StringServerKey,
        n: usize,
        s: &str,
        pattern: &str,
    ) {
        let std_rsplit: Vec<String> = s.rsplitn(n, pattern).map(|s| String::from(s)).collect();
        let encrypted_s = client_key.encrypt_str_padding(s, 3).unwrap();
        let encrypted_pattern = client_key.encrypt_str_padding(pattern, 3).unwrap();
        let fhe_rsplit = server_key.rsplit_clear_n_encrypted(n, &encrypted_s, &encrypted_pattern);
        let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
        //  assert_eq!(clear_len, std_rsplit.len() as u8);
        let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(std_rsplit.len() as usize)]
            .iter()
            .map(|s| client_key.decrypt_string(s).unwrap())
            .collect();
        assert_eq!(clear_rsplit, std_rsplit);
    }

    // pub fn test_rsplit_encrypted_n(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     n: usize,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplitn(n, pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key.encrypt_str_random_padding(s, 2).unwrap();
    //     let encrypted_pattern = client_key.encrypt_str_random_padding(pattern, 2).unwrap();
    //     let encrypted_n = server_key.create_n(n as u8);
    //     let fhe_rsplit = server_key.rsplit_encrypted_n_encrypted_pattern(
    //         &encrypted_n,
    //         &encrypted_s,
    //         &encrypted_pattern,
    //     );
    //     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(std_rsplit.len() as usize)]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    // }

    #[test]
    fn test_test_rsplit_clear_n2() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 2, "cbca", "c");
    }

    #[test]
    fn test_test_rsplit_clear_n3() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 5, "cbca", "c");
    }

    #[test]
    fn test_test_rsplit_clear_n4() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 0, "cbca", "c");
    }

    #[test]
    fn test_test_rsplit_clear_n5() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 3, "cbca", "c");
    }

    #[test]
    fn test_test_rsplit_clear_n6() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 0, "cbca", "");
    }

    #[test]
    fn test_test_rsplit_clear_n7() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 2, "cbca", "");
    }

    #[test]
    fn test_test_rsplit_clear_n8() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 4, "cbca", "");
    }

    #[test]
    fn test_test_rsplit_clear_n9() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 5, "cbca", "");
    }

    #[test]
    fn test_test_rsplit_clear_n10() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 6, "cbca", "");
    }

    #[test]
    fn test_test_rsplit_clear_n11() {
        test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 7, "cbca", "");
    }

    // #[test]
    // fn test_test_rsplit() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "acbccbcbcbc", "cbc");
    // }

    // #[test]
    // fn test_test_rsplit2() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "aczb", "");
    // }

    // #[test]
    // fn test_rsplit_encrypted_final_padding_allow_empty_pattern() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_padding("a", 0).unwrap();
    //     let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("a", 0).unwrap();

    //     let result = SERVER_KEY
    //         .rsplit_encrypted_final_padding_allow_empty_pattern(&encrypted_str,
    // &encrypted_pattern);     let clear_result = (
    //         CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
    //         CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
    //         //	    CLIENT_KEY.decrypt_string(&result.parts[2]).unwrap(),
    //     );

    //     assert_eq!(clear_result, (String::from(""), String::from("")));
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 2);
    // }
}
