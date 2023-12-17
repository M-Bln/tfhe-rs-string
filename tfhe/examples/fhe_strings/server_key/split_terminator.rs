use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

impl StringServerKey {
    pub fn split_terminator(&self, s: &FheString, pattern: &impl FhePattern) -> FheSplit {
        pattern.split_terminator_string(self, s)
    }

    pub fn split_terminator_encrypted(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        match &pattern.length {
            ClearOrEncrypted::Clear(0) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_terminator_empty_pattern(s1, s2)
            }),
            ClearOrEncrypted::Clear(_) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_terminator_encrypted_final_padding(s1, s2)
            }),
            _ => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_terminator_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
        }
    }

    pub fn split_terminator_clear(&self, s: &FheString, pattern: &str) -> FheSplit {
        let empty_fhe_string = FheString {
            content: vec![],
            length: FheStrLength::Clear(0),
            padding: Padding::None,
        };
        match s.len() {
            FheStrLength::Clear(0) if pattern.len() == 0 => {
                return FheSplit {
                    parts: vec![empty_fhe_string],
                    number_parts: self.create_n(1),
                    current_index: 0,
                }
            }
            _ if s.content.len() == 0 && pattern.len() == 0 => {
                return FheSplit {
                    parts: vec![empty_fhe_string],
                    number_parts: self.create_n(1),
                    current_index: 0,
                }
            }
            FheStrLength::Clear(0) => {
                return FheSplit {
                    parts: vec![],
                    number_parts: self.create_n(0),
                    current_index: 0,
                }
            }
            _ if s.content.len() == 0 => {
                return FheSplit {
                    parts: vec![],
                    number_parts: self.create_n(0),
                    current_index: 0,
                }
            }
            FheStrLength::Clear(clear_length) if *clear_length < pattern.len() => {
                return FheSplit {
                    parts: vec![s.clone()],
                    number_parts: self.create_n(1),
                    current_index: 0,
                }
            }
            _ if s.content.len() < pattern.len() => {
                return FheSplit {
                    parts: vec![s.clone()],
                    number_parts: self.create_n(1),
                    current_index: 0,
                }
            }
            _ => (),
        }

        match s.padding {
            _ if pattern.len() == 0 => self
                .padding_pair_dispatch(s, s, |s1, s2| self.split_terminator_empty_pattern(s1, s2)),
            Padding::None | Padding::Final => self.split_terminator_clear_final_padding(s, pattern),
            _ => self.split_terminator_clear_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn split_terminator_char(&self, s: &FheString, pattern: &impl FheCharPattern) -> FheSplit {
        match s.len() {
            FheStrLength::Clear(0) => {
                return FheSplit {
                    parts: vec![],
                    number_parts: self.create_zero(),
                    current_index: 0,
                }
            }
            _ if s.content.len() == 0 => {
                return FheSplit {
                    parts: vec![],
                    number_parts: self.create_zero(),
                    current_index: 0,
                }
            }
            _ => (),
        }
        match s.padding {
            Padding::None | Padding::Final => self.split_terminator_char_final_padding(s, pattern),
            _ => self.split_terminator_char_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn split_terminator_encrypted_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if not empty.
                                                                                    //let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let mut trailing_empty_string = self.create_false();
        for _ in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.add_length_to_radix(&end_part, &pattern.length);
            trailing_empty_string = match &s.length {
                FheStrLength::Clear(clear_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .scalar_eq_parallelized(&start_part, *clear_length as u64),
                ),
                FheStrLength::Encrypted(encrypted_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .eq_parallelized(&start_part, encrypted_length),
                ),
            }
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_terminator_clear_final_padding(&self, s: &FheString, pattern: &str) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length / pattern.len() + 1,
            _ => s.content.len() / pattern.len() + 1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if not empty.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let mut trailing_empty_string = self.create_false();
        for _ in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_clear_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self
                .integer_key
                .scalar_add_parallelized(&end_part, pattern.len() as u8);
            trailing_empty_string = match &s.length {
                FheStrLength::Clear(clear_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .scalar_eq_parallelized(&start_part, *clear_length as u64),
                ),
                FheStrLength::Encrypted(encrypted_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .eq_parallelized(&start_part, encrypted_length),
                ),
            };
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_terminator_char_final_padding(
        &self,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length,
            _ => s.content.len(),
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if not empty.
                                                                                    //        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let mut trailing_empty_string = self.create_false();
        for _ in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_char_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.integer_key.scalar_add_parallelized(&end_part, 1);
            trailing_empty_string = match &s.length {
                FheStrLength::Clear(clear_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .scalar_eq_parallelized(&start_part, *clear_length as u64),
                ),
                FheStrLength::Encrypted(encrypted_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .eq_parallelized(&start_part, encrypted_length),
                ),
            };
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_terminator_encrypted_final_padding_allow_empty_pattern(
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
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if not empty.
                                                                                    //        let mut number_parts = self.create_n(1); // The result has at least 1 part.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let empty_pattern = self.is_empty_encrypted(&pattern);
        let mut trailing_empty_string = self.create_false();
        for n in 0..maximum_number_of_parts {
            let found: BooleanBlock;
            let end_part: RadixCiphertext;
            if n >= 1 {
                // When the patern is empty, the search must start at `start_part` plus 1.
                (found, end_part) = self.find_from_final_padding_allow_empty_pattern(
                    s,
                    pattern,
                    &self
                        .integer_key
                        .add_parallelized(&start_part, &self.bool_to_radix(&empty_pattern)),
                );
            } else {
                (found, end_part) =
                    self.find_from_final_padding_allow_empty_pattern(s, pattern, &start_part);
            }

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.add_length_to_radix(&end_part, &pattern.length);

            trailing_empty_string = match &s.length {
                FheStrLength::Clear(clear_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .scalar_eq_parallelized(&start_part, *clear_length as u64),
                ),
                FheStrLength::Encrypted(encrypted_length) => self.integer_key.boolean_bitor(
                    &trailing_empty_string,
                    &self
                        .integer_key
                        .eq_parallelized(&start_part, encrypted_length),
                ),
            };
        }
        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &empty_pattern,
            &self.add_length_scalar(&s.length, 2),
            &number_parts,
        );
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn split_terminator_empty_pattern(
        &self,
        s: &FheString,
        _empty_pattern: &FheString,
    ) -> FheSplit {
        let max_number_parts = s.content.len() + 1;
        let mut parts: Vec<FheString> = Vec::with_capacity(max_number_parts);
        let number_parts: RadixCiphertext = match &s.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_add_parallelized(encrypted_length, 1),
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length + 1) as u8),
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
                length: ClearOrEncrypted::Encrypted(self.bool_to_radix(&current_char_non_null)),
                content: vec![c.clone()],
            })
        }
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys_test;
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_fhe_split_char_pattern, test_fhe_split_string_pattern};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    test_fhe_split_string_pattern!(split_terminator, "", "e");
    test_fhe_split_string_pattern!(split_terminator, "", "");
    test_fhe_split_string_pattern!(split_terminator, "", "ab");
    test_fhe_split_string_pattern!(split_terminator, "abc", "ab");
    test_fhe_split_string_pattern!(split_terminator, "cbca", "c");
    test_fhe_split_string_pattern!(split_terminator, "acbc", "bc");
    test_fhe_split_string_pattern!(split_terminator, "acbccbcbcbc", "cbc");
    test_fhe_split_string_pattern!(split_terminator, "aczb", "");
    test_fhe_split_string_pattern!(split_terminator, "aaaaa", "aa");
    test_fhe_split_string_pattern!(split_terminator, "axbx", "x");
    test_fhe_split_string_pattern!(split_terminator, "ab", "ab");
    test_fhe_split_string_pattern!(split_terminator, "abab", "ab");

    test_fhe_split_char_pattern!(split_terminator, "", 'a');
    test_fhe_split_char_pattern!(split_terminator, "a", 'a');
    test_fhe_split_char_pattern!(split_terminator, "acbc", 'c');
    test_fhe_split_char_pattern!(split_terminator, "cccc", 'c');
    test_fhe_split_char_pattern!(split_terminator, "cabd", 'a');
    test_fhe_split_char_pattern!(split_terminator, "cacb", 'c');
}
