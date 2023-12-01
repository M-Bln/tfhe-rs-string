use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn rsplit_encrypted(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        match &pattern.length {
            ClearOrEncrypted::Clear(0) => {
                self.padding_pair_dispatch(s, pattern, |s1, s2| self.rsplit_empty_pattern(s1, s2))
            }
            ClearOrEncrypted::Clear(_) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
            _ => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
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
        let mut end_part = self.length_to_radix_plus_one(&s.length);

        for n in (0..maximum_number_of_parts).rev() {
            let start_pattern: RadixCiphertext;
            (found, start_pattern) =
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
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
        }

        // // Correct number of parts if the pattern is empty
        // self.integer_key.sub_assign_parallelized(&mut number_parts,
        // &self.is_empty_encrypted(pattern));

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

    #[test]
    fn test_rsplit_encrypted_final_padding_allow_empty_pattern() {
        let encrypted_str = CLIENT_KEY.encrypt_str_padding("a", 0).unwrap();
        let encrypted_pattern = CLIENT_KEY.encrypt_str_padding("a", 0).unwrap();

        let result = SERVER_KEY
            .rsplit_encrypted_final_padding_allow_empty_pattern(&encrypted_str, &encrypted_pattern);
        let clear_result = (
            CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
            CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
            //	    CLIENT_KEY.decrypt_string(&result.parts[2]).unwrap(),
        );

        assert_eq!(clear_result, (String::from(""), String::from("")));
        assert_eq!(CLIENT_KEY.decrypt_u8(&result.number_parts), 2);
    }
}
