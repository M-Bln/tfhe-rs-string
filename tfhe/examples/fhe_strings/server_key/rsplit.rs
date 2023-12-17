use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
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
            (Padding::None | Padding::Initial, _) => f(s1, &self.push_padding_to_start(s2)),
            (_, Padding::None | Padding::Initial) => f(&self.push_padding_to_start(s1), s2),
            _ => f(
                &self.push_padding_to_start(s1),
                &self.push_padding_to_start(s2),
            ),
        }
    }

    pub fn rsplit(&self, s: &FheString, pattern: &impl FhePattern) -> FheSplit {
        pattern.rsplit_string(self, s)
    }

    pub fn rsplit_terminator(&self, s: &FheString, pattern: &impl FhePattern) -> FheSplit {
        pattern.rsplit_terminator_string(self, s)
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

    pub fn rsplit_clear(&self, s: &FheString, pattern: &str) -> FheSplit {
        match s.len() {
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
            _ if pattern.is_empty() => {
                self.rpadding_pair_dispatch(s, s, |s1, s2| self.rsplit_empty_pattern(s1, s2))
            }
            Padding::None | Padding::Final => self.rsplit_clear_final_padding(s, pattern),
            _ => self.rsplit_clear_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn rsplit_char(&self, s: &FheString, pattern: &impl FheCharPattern) -> FheSplit {
        match s.padding {
            Padding::None | Padding::Final => self.rsplit_char_final_padding(s, pattern),
            _ => self.rsplit_char_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn rsplit_terminator_char(&self, s: &FheString, pattern: &impl FheCharPattern) -> FheSplit {
        match s.len() {
            FheStrLength::Clear(0) => {
                return FheSplit {
                    parts: vec![],
                    number_parts: self.create_zero(),
                    current_index: 0,
                }
            }
            _ if s.content.is_empty() => {
                return FheSplit {
                    parts: vec![],
                    number_parts: self.create_zero(),
                    current_index: 0,
                }
            }
            _ => (),
        }
        match s.padding {
            Padding::None | Padding::Final => self.rsplit_terminator_char_final_padding(s, pattern),
            _ => self.rsplit_terminator_char_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn rsplit_terminator_encrypted(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        match &pattern.length {
            ClearOrEncrypted::Clear(0) => self.rpadding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_terminator_empty_pattern(s1, s2)
            }),
            ClearOrEncrypted::Clear(_) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_terminator_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
            _ => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.rsplit_terminator_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
        }
    }

    pub fn rsplit_terminator_clear(&self, s: &FheString, pattern: &str) -> FheSplit {
        let empty_fhe_string = FheString {
            content: vec![],
            length: FheStrLength::Clear(0),
            padding: Padding::None,
        };
        match s.len() {
            FheStrLength::Clear(0) if pattern.is_empty() => {
                return FheSplit {
                    parts: vec![empty_fhe_string],
                    number_parts: self.create_n(1),
                    current_index: 0,
                }
            }
            _ if s.content.is_empty() && pattern.is_empty() => {
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
            _ if s.content.is_empty() => {
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
            _ if pattern.is_empty() => self.rpadding_pair_dispatch(s, s, |s1, s2| {
                self.rsplit_terminator_empty_pattern(s1, s2)
            }),
            Padding::None | Padding::Final => {
                self.rsplit_terminator_clear_final_padding(s, pattern)
            }
            _ => self.rsplit_terminator_clear_final_padding(&self.push_padding_to_end(s), pattern),
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
                length: ClearOrEncrypted::Encrypted(self.bool_to_radix(&current_char_non_null)),
                content: vec![c.clone()],
            })
        }
        parts.push(empty_string);
        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_terminator_empty_pattern(
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
        //        parts.push(empty_string.clone());
        for c in s.content.iter().rev() {
            let current_char_non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
            parts.push(FheString {
                padding: Padding::Final,
                length: ClearOrEncrypted::Encrypted(self.bool_to_radix(&current_char_non_null)),
                content: vec![c.clone()],
            })
        }
        parts.push(empty_string);
        FheSplit {
            parts,
            number_parts,
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
    //             length: ClearOrEncrypted::Encrypted(self.bool_to_radix(&current_char_non_null)),
    //             content: vec![c.clone()],
    //         })
    //     }
    //     for c in s.content.iter().rev() {
    //         let current_char_non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
    //         parts.push(FheString {
    //             padding: Padding::Final,
    //             length: ClearOrEncrypted::Encrypted(self.bool_to_radix(&current_char_non_null)),
    //             content: vec![c.clone()],
    //         })
    //     }
    //     parts.push(empty_string);
    //     FheSplit {
    //         parts,
    //         number_parts,
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
    //     let zero = self.create_zero(); let fhe_false = self.create_false();
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
    //         parts,
    //         number_parts,
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
    //     let zero = self.create_zero(); let fhe_false = self.create_false();
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
    //         parts,
    //         number_parts,
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

        for _ in (0..maximum_number_of_parts).rev() {
            let (found, start_pattern) =
                self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self.add_length_to_radix(&start_pattern, &pattern.length),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = start_pattern;
        }
        FheSplit {
            parts,
            number_parts,
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
        let mut found;

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        let empty_pattern = self.is_empty_encrypted(pattern);
        let decrement_search_from = self.integer_key.cmux_parallelized(
            &empty_pattern,
            &zero.clone(),
            &self.sub_scalar_to_length(&pattern.length, 1),
        );

        for i in 0..maximum_number_of_parts {
            let start_pattern: RadixCiphertext;
            if i > 0 {
                let search_from = self.integer_key.cmux_parallelized(
                    &self
                        .integer_key
                        .ge_parallelized(&end_part, &decrement_search_from),
                    &self
                        .integer_key
                        .sub_parallelized(&end_part, &decrement_search_from),
                    &zero.clone(),
                );

                (found, start_pattern) =
                    self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &search_from);
            } else {
                (found, start_pattern) =
                    self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);
            }

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

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
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_clear_final_padding(&self, s: &FheString, pattern: &str) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.
        let mut found;

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(0), &s.length);

        let decrement_search_from = (pattern.len() - 1) as u64;

        for i in 0..maximum_number_of_parts {
            let start_pattern: RadixCiphertext;
            if i > 0 {
                let search_from = self.integer_key.cmux_parallelized(
                    &self
                        .integer_key
                        .scalar_ge_parallelized(&end_part, decrement_search_from),
                    &self
                        .integer_key
                        .scalar_sub_parallelized(&end_part, decrement_search_from),
                    &zero.clone(),
                );

                (found, start_pattern) =
                    self.rfind_clear_from_final_padding(s, pattern, &search_from);
            } else {
                (found, start_pattern) = self.rfind_clear_from_final_padding(s, pattern, &end_part);
            }

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self
                    .integer_key
                    .scalar_add_parallelized(&start_pattern, pattern.len() as u64),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_char_final_padding(
        &self,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1); // The result has at least 1 part.
        let mut found;

        let mut end_part = self.add_length_to_radix(&self.create_n(0), &s.length);

        for _ in 0..maximum_number_of_parts {
            let start_pattern: RadixCiphertext;

            (found, start_pattern) = self.rfind_char_from_final_padding(s, pattern, &end_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self.integer_key.scalar_add_parallelized(&start_pattern, 1),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_terminator_encrypted_final_padding_allow_empty_pattern(
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
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if s is non-empty 0 otherwise.

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(0), &s.length);
        let empty_pattern = self.is_empty_encrypted(pattern);
        let decrement_search_from = self.integer_key.cmux_parallelized(
            &empty_pattern,
            &zero.clone(),
            &self.sub_scalar_to_length(&pattern.length, 1),
        );

        let (mut found, mut start_pattern) =
            self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);
        let has_trailing_empty_string = self.integer_key.boolean_bitand(
            &found,
            &self.integer_key.eq_parallelized(
                &self.add_length_to_radix(&start_pattern, &pattern.length),
                &self.add_length_to_radix(&self.create_zero(), &s.length),
            ),
        );
        let mut search_from = self.integer_key.cmux_parallelized(
            &has_trailing_empty_string,
            &self.integer_key.cmux_parallelized(
                &self
                    .integer_key
                    .ge_parallelized(&start_pattern, &decrement_search_from),
                &self
                    .integer_key
                    .sub_parallelized(&start_pattern, &decrement_search_from),
                &zero,
            ),
            &end_part,
        );
        end_part = self.integer_key.cmux_parallelized(
            &has_trailing_empty_string,
            &start_pattern,
            &end_part,
        );
        // let mut start_part = self.integer_key.cmux_parallelized(
        //     &has_trailing_empty_string,
        //     ,
        //     &start_part,
        // )
        for i in 0..maximum_number_of_parts {
            if i > 0 {
                search_from = self.integer_key.cmux_parallelized(
                    &self
                        .integer_key
                        .ge_parallelized(&end_part, &decrement_search_from),
                    &self
                        .integer_key
                        .sub_parallelized(&end_part, &decrement_search_from),
                    &zero.clone(),
                );

                (found, start_pattern) =
                    self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &search_from);
            } else {
                (found, start_pattern) =
                    self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &search_from);
            }

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self.add_length_to_radix(&start_pattern, &pattern.length),
                &zero,
            );
            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
        }

        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &empty_pattern,
            &self.add_length_scalar(&s.length, 1),
            &number_parts,
        );

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_terminator_clear_final_padding(&self, s: &FheString, pattern: &str) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length,
            _ => s.content.len(),
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if s is non-empty 0 otherwise.

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        let decrement_search_from = (pattern.len() - 1) as u64;
        //	let initial_decrement_search_from = (pattern.len() - 1) as u64;

        let (mut found, mut start_pattern) =
            self.rfind_clear_from_final_padding(s, pattern, &end_part);
        let has_trailing_empty_string = self.integer_key.boolean_bitand(
            &found,
            &self.integer_key.eq_parallelized(
                &self
                    .integer_key
                    .scalar_add_parallelized(&start_pattern, pattern.len() as u64),
                &self.add_length_to_radix(&self.create_zero(), &s.length),
            ),
        );

        let mut search_from = self.integer_key.cmux_parallelized(
            &has_trailing_empty_string,
            &self.integer_key.cmux_parallelized(
                &self
                    .integer_key
                    .scalar_ge_parallelized(&start_pattern, decrement_search_from),
                &self
                    .integer_key
                    .scalar_sub_parallelized(&start_pattern, decrement_search_from),
                &zero,
            ),
            &end_part,
        );

        end_part = self.integer_key.cmux_parallelized(
            &has_trailing_empty_string,
            &start_pattern,
            &end_part,
        );

        // let mut start_part = self.integer_key.cmux_parallelized(
        //     &has_trailing_empty_string,
        //     ,
        //     &start_part,
        // )
        for i in 0..maximum_number_of_parts {
            if i > 0 {
                search_from = self.integer_key.cmux_parallelized(
                    &self
                        .integer_key
                        .scalar_ge_parallelized(&end_part, decrement_search_from),
                    &self
                        .integer_key
                        .scalar_sub_parallelized(&end_part, decrement_search_from),
                    &zero.clone(),
                );

                (found, start_pattern) =
                    self.rfind_clear_from_final_padding(s, pattern, &search_from);
            } else {
                (found, start_pattern) =
                    self.rfind_clear_from_final_padding(s, pattern, &search_from);
            }

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self
                    .integer_key
                    .scalar_add_parallelized(&start_pattern, pattern.len() as u64),
                &zero,
            );
            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_terminator_char_final_padding(
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
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if s is non-empty 0 otherwise.

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_zero(), &s.length);

        let (mut found, mut start_pattern) =
            self.rfind_char_from_final_padding(s, pattern, &end_part);
        let has_trailing_empty_string = self.integer_key.boolean_bitand(
            &found,
            &self.integer_key.eq_parallelized(
                &self.integer_key.scalar_add_parallelized(&start_pattern, 1),
                &self.add_length_to_radix(&self.create_zero(), &s.length),
            ),
        );
        end_part = self.integer_key.cmux_parallelized(
            &has_trailing_empty_string,
            &start_pattern,
            &end_part,
        );
        // let mut start_part = self.integer_key.cmux_parallelized(
        //     &has_trailing_empty_string,
        //     ,
        //     &start_part,
        // )
        for _ in 0..maximum_number_of_parts {
            (found, start_pattern) = self.rfind_char_from_final_padding(s, pattern, &end_part);

            let start_part = self.integer_key.cmux_parallelized(
                &found,
                &self.integer_key.scalar_add_parallelized(&start_pattern, 1),
                &zero,
            );
            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            end_part = self
                .integer_key
                .cmux_parallelized(&found, &start_pattern, &zero);
        }

        FheSplit {
            parts,
            number_parts,
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
    //     let zero = self.create_zero(); let fhe_false = self.create_false();
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
    //             .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

    //         let start_part = self.integer_key.cmux_parallelized(
    //             &found,
    //             &self.add_length_to_radix(&start_pattern, &pattern.length),
    //             &zero,
    //         );

    //         parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
    //         end_part = start_pattern;
    //     }
    //     FheSplit {
    //         parts,
    //         number_parts,
    //         current_index: 0,
    //     }
    // }
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

    //test_fhe_split_string_pattern!(rsplit, "", "e");
    // test_fhe_split_string_pattern!(rsplit, "", "");
    // test_fhe_split_string_pattern!(rsplit, "", "ab");
    // test_fhe_split_string_pattern!(rsplit, "acbc", "c");
    // test_fhe_split_string_pattern!(rsplit, "acbccbcbcbc", "cbc");
    // test_fhe_split_string_pattern!(rsplit, "aczb", "");
    // test_fhe_split_string_pattern!(rsplit, "aaaaa", "a");
    // test_fhe_split_string_pattern!(rsplit, "axbx", "x");
    // test_fhe_split_string_pattern!(rsplit, "ab", "ab");
    // test_fhe_split_string_pattern!(rsplit, "abab", "ab");

    // test_fhe_split_char_pattern!(rsplit, "", 'a');
    // test_fhe_split_char_pattern!(rsplit, "a", 'a');
    // test_fhe_split_char_pattern!(rsplit, "acbc", 'c');
    // test_fhe_split_char_pattern!(rsplit, "cccc", 'c');
    // test_fhe_split_char_pattern!(rsplit, "cabd", 'a');
    // test_fhe_split_char_pattern!(rsplit, "acb", 'c');

    //test_fhe_split_string_pattern!(rsplit_terminator, "", "e");
    //test_fhe_split_string_pattern!(rsplit_terminator, "", "");
    //test_fhe_split_string_pattern!(rsplit_terminator, "", "ab");
    test_fhe_split_string_pattern!(rsplit_terminator, "acbc", "c");
    test_fhe_split_string_pattern!(rsplit_terminator, "cbca", "c");
    test_fhe_split_string_pattern!(rsplit_terminator, "acbc", "bc");
    test_fhe_split_string_pattern!(rsplit_terminator, "acbccbcbcbc", "cbc");
    //test_fhe_split_string_pattern!(rsplit_terminator, "aczb", "");
    test_fhe_split_string_pattern!(rsplit_terminator, "aaaaa", "a");
    test_fhe_split_string_pattern!(rsplit_terminator, "axbx", "x");
    test_fhe_split_string_pattern!(rsplit_terminator, "ab", "ab");
    test_fhe_split_string_pattern!(rsplit_terminator, "abab", "ab");

    //test_fhe_split_char_pattern!(rsplit_terminator, "", 'a');
    test_fhe_split_char_pattern!(rsplit_terminator, "a", 'a');
    test_fhe_split_char_pattern!(rsplit_terminator, "acbc", 'c');
    test_fhe_split_char_pattern!(rsplit_terminator, "cccc", 'c');
    test_fhe_split_char_pattern!(rsplit_terminator, "cabd", 'a');
    test_fhe_split_char_pattern!(rsplit_terminator, "cacb", 'c');

    // pub fn test_rsplit(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplit(pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key.encrypt_str_padding(s, 2).unwrap();
    //     let encrypted_pattern = client_key.encrypt_str_padding(pattern, 2).unwrap();
    //     let fhe_rsplit = server_key.rsplit_encrypted(&encrypted_s, &encrypted_pattern);
    //     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..std_rsplit.len()]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     // let clear_rsplit: Vec<String> = fhe_rsplit.parts[..6].iter().map(|s|
    //     // client_key.decrypt_string(s).unwrap()).collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    // }

    // pub fn test_rsplit_with_padding(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    //     string_padding: usize,
    //     pattern_padding: usize,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplit(pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key.encrypt_str_padding(s, string_padding).unwrap();
    //     let encrypted_pattern = client_key
    //         .encrypt_str_padding(pattern, pattern_padding)
    //         .unwrap();
    //     let fhe_rsplit = server_key.rsplit_encrypted(&encrypted_s, &encrypted_pattern);
    //     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..std_rsplit.len()]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     // let clear_rsplit: Vec<String> = fhe_rsplit.parts[..6].iter().map(|s|
    //     // client_key.decrypt_string(s).unwrap()).collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    // }

    // pub fn test_rsplit_terminator_with_padding(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    //     string_padding: usize,
    //     pattern_padding: usize,
    // ) {
    //     let std_rsplit_terminator: Vec<String> = s
    //         .rsplit_terminator(pattern)
    //         .map(|s| String::from(s))
    //         .collect();
    //     let encrypted_s = client_key.encrypt_str_padding(s, string_padding).unwrap();
    //     let encrypted_pattern = client_key
    //         .encrypt_str_padding(pattern, pattern_padding)
    //         .unwrap();
    //     let fhe_rsplit_terminator =
    //         server_key.rsplit_terminator_encrypted(&encrypted_s, &encrypted_pattern);
    //     let clear_len = client_key.decrypt_u8(&fhe_rsplit_terminator.number_parts);
    //     let clear_rsplit_terminator: Vec<String> = fhe_rsplit_terminator.parts
    //         [..std_rsplit_terminator.len()]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     // let clear_rsplit_terminator: Vec<String> =
    //     // fhe_rsplit_terminator.parts[..6].iter().map(|s| client_key.decrypt_string(s).
    //     // unwrap()).collect();
    //     assert_eq!(clear_rsplit_terminator, std_rsplit_terminator);
    //     assert_eq!(clear_len, std_rsplit_terminator.len() as u8);
    // }

    // pub fn test_rsplit_terminator(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     let std_rsplit_terminator: Vec<String> = s
    //         .rsplit_terminator(pattern)
    //         .map(|s| String::from(s))
    //         .collect();
    //     let encrypted_s = client_key.encrypt_str_padding(s, 2).unwrap();
    //     let encrypted_pattern = client_key.encrypt_str_padding(pattern, 2).unwrap();
    //     let fhe_rsplit_terminator =
    //         server_key.rsplit_terminator_encrypted(&encrypted_s, &encrypted_pattern);
    //     let clear_len = client_key.decrypt_u8(&fhe_rsplit_terminator.number_parts);
    //     let clear_rsplit_terminator: Vec<String> = fhe_rsplit_terminator.parts
    //         [..std_rsplit_terminator.len()]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     // let clear_rsplit_terminator: Vec<String> =
    //     // fhe_rsplit_terminator.parts[..6].iter().map(|s| client_key.decrypt_string(s).
    //     // unwrap()).collect();
    //     assert_eq!(clear_rsplit_terminator, std_rsplit_terminator);
    //     assert_eq!(clear_len, std_rsplit_terminator.len() as u8);
    // }

    // pub fn test_rsplit_clear_n(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     n: usize,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplitn(n, pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key.encrypt_str_padding(s, 3).unwrap();
    //     let encrypted_pattern = client_key.encrypt_str_padding(pattern, 3).unwrap();
    //     let fhe_rsplit = server_key.rsplit_clear_n_encrypted(n, &encrypted_s,
    // &encrypted_pattern);     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(std_rsplit.len() as usize)]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    // }

    // pub fn test_rsplit_clear_n_with_padding(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     n: usize,
    //     s: &str,
    //     pattern: &str,
    //     string_padding: usize,
    //     pattern_padding: usize,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplitn(n, pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key.encrypt_str_padding(s, string_padding).unwrap();
    //     let encrypted_pattern = client_key
    //         .encrypt_str_padding(pattern, pattern_padding)
    //         .unwrap();
    //     let fhe_rsplit = server_key.rsplit_clear_n_encrypted(n, &encrypted_s,
    // &encrypted_pattern);     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(std_rsplit.len() as usize)]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    // }

    // pub fn test_rsplit_encrypted_n(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     n: usize,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplitn(n, pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key.encrypt_str_random_padding(s, 0).unwrap();
    //     let encrypted_pattern = client_key.encrypt_str_random_padding(pattern, 2).unwrap();
    //     let encrypted_n = server_key.create_n(n as u8);
    //     let fhe_rsplit =
    //         server_key.rsplit_encrypted_n_encrypted(&encrypted_n, &encrypted_s,
    // &encrypted_pattern);     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(std_rsplit.len() as usize)]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    // }

    // pub fn test_rsplit_encrypted_n_with_padding(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     n: usize,
    //     s: &str,
    //     pattern: &str,
    //     string_padding: usize,
    //     pattern_padding: usize,
    // ) {
    //     let std_rsplit: Vec<String> = s.rsplitn(n, pattern).map(|s| String::from(s)).collect();
    //     let encrypted_s = client_key
    //         .encrypt_str_random_padding(s, string_padding)
    //         .unwrap();
    //     let encrypted_pattern = client_key
    //         .encrypt_str_random_padding(pattern, pattern_padding)
    //         .unwrap();
    //     let encrypted_n = server_key.create_n(n as u8);
    //     let fhe_rsplit =
    //         server_key.rsplit_encrypted_n_encrypted(&encrypted_n, &encrypted_s,
    // &encrypted_pattern);     let clear_len = client_key.decrypt_u8(&fhe_rsplit.number_parts);
    //     let clear_rsplit: Vec<String> = fhe_rsplit.parts[..(std_rsplit.len() as usize)]
    //         .iter()
    //         .map(|s| client_key.decrypt_string(s).unwrap())
    //         .collect();
    //     assert_eq!(clear_rsplit, std_rsplit);
    //     assert_eq!(clear_len, std_rsplit.len() as u8);
    // }

    // pub fn full_test_rsplit_encrypted_n(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 0, s, pattern, 2, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 0, s, pattern, 0, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 0, s, pattern, 2, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 0, s, pattern, 0, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 1, s, pattern, 2, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 1, s, pattern, 0, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 1, s, pattern, 2, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 1, s, pattern, 0, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 2, s, pattern, 2, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 2, s, pattern, 0, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 2, s, pattern, 2, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, 2, s, pattern, 0, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len(), s, pattern, 2, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len(), s, pattern, 0, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len(), s, pattern, 2, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len(), s, pattern, 0, 0);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len() + 1, s, pattern, 2,
    // 2);     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len() + 1, s,
    // pattern, 0, 2);     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len()
    // + 1, s, pattern, 2, 0);     test_rsplit_encrypted_n_with_padding(client_key, server_key,
    // s.len() + 1, s, pattern, 0, 0);     test_rsplit_encrypted_n_with_padding(client_key,
    // server_key, s.len() + 4, s, pattern, 2, 2);
    //     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len() + 4, s, pattern, 0,
    // 2);     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len() + 4, s,
    // pattern, 2, 0);     test_rsplit_encrypted_n_with_padding(client_key, server_key, s.len()
    // + 4, s, pattern, 0, 0); }

    // pub fn full_test_rsplit_clear_n(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 0, s, pattern, 2, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 0, s, pattern, 0, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 0, s, pattern, 2, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 0, s, pattern, 0, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 1, s, pattern, 2, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 1, s, pattern, 0, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 1, s, pattern, 2, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 1, s, pattern, 0, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 2, s, pattern, 2, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 2, s, pattern, 0, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 2, s, pattern, 2, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, 2, s, pattern, 0, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len(), s, pattern, 2, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len(), s, pattern, 0, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len(), s, pattern, 2, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len(), s, pattern, 0, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 1, s, pattern, 2, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 1, s, pattern, 0, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 1, s, pattern, 2, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 1, s, pattern, 0, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 4, s, pattern, 2, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 4, s, pattern, 0, 2);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 4, s, pattern, 2, 0);
    //     test_rsplit_clear_n_with_padding(client_key, server_key, s.len() + 4, s, pattern, 0, 0);
    // }

    // pub fn full_test_rsplit_terminator(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     test_rsplit_terminator_with_padding(client_key, server_key, s, pattern, 2, 2);
    //     test_rsplit_terminator_with_padding(client_key, server_key, s, pattern, 0, 2);
    //     test_rsplit_terminator_with_padding(client_key, server_key, s, pattern, 2, 0);
    //     test_rsplit_terminator_with_padding(client_key, server_key, s, pattern, 0, 0);
    // }

    // pub fn full_test_rsplit(
    //     client_key: &StringClientKey,
    //     server_key: &StringServerKey,
    //     s: &str,
    //     pattern: &str,
    // ) {
    //     test_rsplit_with_padding(client_key, server_key, s, pattern, 2, 2);
    //     test_rsplit_with_padding(client_key, server_key, s, pattern, 0, 2);
    //     test_rsplit_with_padding(client_key, server_key, s, pattern, 2, 0);
    //     test_rsplit_with_padding(client_key, server_key, s, pattern, 0, 0);
    // }
    // #[test]
    // fn test_test_rsplit_clear_n2() {
    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 5, "ccccc", "cc");
    // }

    // #[test]
    // fn test_test_rsplit_clear_n3() {
    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 5, "cbca", "c");
    // }

    // #[test]
    // fn test_test_rsplit_clear_n4() {
    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 0, "cbca", "c");
    // }    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 4, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_clear_n9() {
    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 5, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_clear_n10() {
    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 6, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_clear_n11() {
    //     test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, 7, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n2() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 5, "ccccc", "cc");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n3() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 5, "cbca", "c");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n4() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 0, "cbca", "c");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n5() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 3, "cbca", "c");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n6() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 0, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n7() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 2, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n8() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 4, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n9() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 5, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n10() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 6, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit_encrypted_n11() {
    //     test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, 7, "cbca", "");
    // }

    // #[test]
    // fn test_test_rsplit() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "acbccbcbcbc", "cbc");
    // }

    // #[test]
    // fn test_test_rsplit2() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "aczb", "");
    // }

    // #[test]
    // fn test_test_rsplit3() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "aaaaa", "aa");
    // }

    // #[test]
    // fn test_test_rsplit4() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "a.b.", ".");
    // }

    // #[test]
    // fn test_test_rsplit5() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "ab", "ab");
    // }

    // #[test]
    // fn test_test_rsplit6() {
    //     test_rsplit(&CLIENT_KEY, &SERVER_KEY, "abab", "ab");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator1() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator2() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "aaa", "a");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator3() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "aaa", "");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator4() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator5() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, ".a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator6() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, ".a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_terminator7() {
    //     full_test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "ababa", "ab");
    // }

    // #[test]
    // fn test_full_test_rsplit1() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, "a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit2() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, "aaa", "a");
    // }

    // #[test]
    // fn test_full_test_rsplit3() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, "aaa", "");
    // }

    // #[test]
    // fn test_full_test_rsplit4() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, "a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit5() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, ".a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit6() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, ".a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit7() {
    //     full_test_rsplit(&CLIENT_KEY, &SERVER_KEY, "ababa", "ab");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n1() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, "a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n2() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, "aaa", "a");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n3() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, "aaa", "");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n_empty_empty() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, "", "");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n4() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, "a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n5() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, ".a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n6() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, ".a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_clear_n7() {
    //     full_test_rsplit_clear_n(&CLIENT_KEY, &SERVER_KEY, "ababa", "ab");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n1() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, "a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n2() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, "aaa", "a");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n3() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, "aaa", "");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n_empty_empty() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, "", "");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n4() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, "a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n5() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, ".a.b", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n6() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, ".a.b.", ".");
    // }

    // #[test]
    // fn test_full_test_rsplit_encrypted_n7() {
    //     full_test_rsplit_encrypted_n(&CLIENT_KEY, &SERVER_KEY, "ababa", "ab");
    // }

    // #[test]
    // fn test_test_rsplit_terminator4() {
    //     test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "a.b.", ".");
    // }

    // #[test]
    // fn test_test_rsplit_terminator5() {
    //     test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "ab", "ab");
    // }

    // #[test]
    // fn test_test_rsplit_terminator6() {
    //     test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "abab", "ab");
    // }

    // #[test]
    // fn test_test_rsplit_terminator7() {
    //     test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "aaaa", "a");
    // }

    // #[test]
    // fn test_test_rsplit_terminator8() {
    //     test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "abab", "");
    // }

    // #[test]
    // fn test_test_rsplit_terminator9() {
    //     test_rsplit_terminator(&CLIENT_KEY, &SERVER_KEY, "", "");
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
