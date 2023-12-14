use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::integer_arg::FheIntegerArg;
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn rpadding_dispatch<F>(&self, s: &FheString, f: F) -> FheSplit
    where
        F: Fn(&FheString) -> FheSplit,
    {
        match s.padding {
            Padding::None | Padding::Initial => f(s),
            _ => f(&self.remove_final_padding(s)),
        }
    }

    pub fn rsplitn(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &impl FhePattern,
    ) -> FheSplit {
        pattern.rsplitn_string(self, n, s)
    }

    pub fn rsplitn_encrypted_string(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        n.rsplitn_encrypted_string(self, s, pattern)
    }

    pub fn rsplitn_clear_string(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        n.rsplitn_clear_string_pattern(self, s, pattern)
    }

    pub fn rsplitn_char(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        n.rsplitn_char_pattern(self, s, pattern)
    }

    pub fn rsplit_clear_n_encrypted_string(
        &self,
        n: usize,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        self.padding_pair_dispatch(s, pattern, |s1, s2| {
            self.rsplit_clear_n_encrypted_final_padding_allow_empty_pattern(n, s1, s2)
        })
    }

    pub fn rsplit_encrypted_n_encrypted_string(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        self.padding_pair_dispatch(s, pattern, |s1, s2| {
            self.rsplit_encrypted_n_encrypted_final_padding_allow_empty_pattern(n, s1, s2)
        })
    }

    pub fn rsplit_clear_n_clear_string(&self, n: usize, s: &FheString, pattern: &str) -> FheSplit {
        if pattern.is_empty() {
            return self.rpadding_dispatch(s, |s1| self.rsplit_clear_n_empty_pattern(n, s1));
        }
        self.padding_dispatch(s, |s1| {
            self.rsplit_clear_n_clear_string_final_padding(n, s1, pattern)
        })
    }

    pub fn rsplit_encrypted_n_clear_string(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        if pattern.is_empty() {
            return self.padding_dispatch(s, |s1| self.rsplit_encrypted_n_empty_pattern(n, s1));
        }
        self.padding_dispatch(s, |s1| {
            self.rsplit_encrypted_n_clear_string_final_padding(n, s1, pattern)
        })
    }

    pub fn rsplit_encrypted_n_char(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        self.padding_dispatch(s, |s1| {
            self.rsplit_encrypted_n_char_final_padding(n, s1, pattern)
        })
    }

    pub fn rsplit_clear_n_char(
        &self,
        n: usize,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        self.padding_dispatch(s, |s1| {
            self.rsplit_clear_n_char_final_padding(n, s1, pattern)
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
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        let empty_pattern = self.is_empty_encrypted(&pattern);
        let decrement_search_from = self.integer_key.cmux_parallelized(
            &empty_pattern,
            &zero.clone(),
            &self.sub_scalar_to_length(&pattern.length, 1),
        );

        for i in 0..maximum_number_of_parts_or_n {
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

    pub fn rsplit_encrypted_n_encrypted_final_padding_allow_empty_pattern(
        &self,
        n: &RadixCiphertext,
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
        let mut number_parts = self.integer_key.scalar_gt_parallelized(n, 0); // The result has at least 1 part as long as n>0
        let mut found = zero.clone();

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        let empty_pattern = self.is_empty_encrypted(&pattern);
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

            let in_range_n = self.integer_key.scalar_gt_parallelized(n, (i + 1) as u64);

            // Increment `number_parts` is the pattern found and in range, i.e., i < n-1
            let found_in_range = self.integer_key.bitand_parallelized(&found, &in_range_n);
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found_in_range);

            // The new part starts at the end of the pattern if it is found in range, at zero
            // otherwise
            let start_part = self.integer_key.cmux_parallelized(
                &found_in_range,
                &self.add_length_to_radix(&start_pattern, &pattern.length),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));

            end_part = self
                .integer_key
                .cmux_parallelized(&found_in_range, &start_pattern, &zero);
        }

        let number_parts_rsplit_empty_pattern = &self.add_length_scalar(&s.length, 2);
        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &self.integer_key.bitand_parallelized(
                &empty_pattern,
                &self
                    .integer_key
                    .le_parallelized(&number_parts_rsplit_empty_pattern, &n),
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

    pub fn rsplit_encrypted_n_clear_string_final_padding(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.integer_key.scalar_gt_parallelized(n, 0); // The result has at least 1 part as long as n>0
        let mut found = zero.clone();

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        // let empty_pattern = self.is_empty_encrypted(&pattern);
        let decrement_search_from = pattern.len() - 1;
        // let decrement_search_from = self.integer_key.cmux_parallelized(
        //     &empty_pattern,
        //     &zero.clone(),
        //     &self.sub_scalar_to_length(&pattern.length, 1),
        // );

        for i in 0..maximum_number_of_parts {
            let start_pattern: RadixCiphertext;
            if i > 0 {
                let search_from = self.integer_key.cmux_parallelized(
                    &self
                        .integer_key
                        .scalar_ge_parallelized(&end_part, decrement_search_from as u32),
                    &self
                        .integer_key
                        .scalar_sub_parallelized(&end_part, decrement_search_from as u32),
                    &zero.clone(),
                );
                (found, start_pattern) =
                    self.rfind_clear_from_final_padding(s, pattern, &search_from);
            } else {
                (found, start_pattern) = self.rfind_clear_from_final_padding(s, pattern, &end_part);
            }

            let in_range_n = self.integer_key.scalar_gt_parallelized(n, (i + 1) as u64);

            // Increment `number_parts` is the pattern found and in range, i.e., i < n-1
            let found_in_range = self.integer_key.bitand_parallelized(&found, &in_range_n);
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found_in_range);

            // The new part starts at the end of the pattern if it is found in range, at zero
            // otherwise
            let start_part = self.integer_key.cmux_parallelized(
                &found_in_range,
                &self
                    .integer_key
                    .scalar_add_parallelized(&start_pattern, pattern.len() as u32),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));

            end_part = self
                .integer_key
                .cmux_parallelized(&found_in_range, &start_pattern, &zero);
        }

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_clear_n_empty_pattern(&self, n: usize, s: &FheString) -> FheSplit {
        if n == 0 {
            return FheSplit {
                parts: vec![],
                number_parts: self.create_zero(),
                current_index: 0,
            };
        }
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts_split = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let maximum_number_of_parts = std::cmp::min(maximum_number_of_parts_split, n);

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        //let mut number_parts = self.integer_key.scalar_gt_parallelized(n, 0);

        if n == 1 {
            parts.push(s.clone());
            return FheSplit {
                parts: parts,
                number_parts: self.create_n(1),
                current_index: 0,
            };
        }
        let empty_string = FheString {
            content: vec![],
            length: FheStrLength::Clear(0),
            padding: Padding::None,
        };
        // Push first empty part
        parts.push(empty_string);
        // Fill in length 1 parts
        for i in 0..(maximum_number_of_parts - 2) {
            parts.push(FheString {
                content: vec![s.content[s.content.len() - 1 - i].clone()],
                length: match s.len() {
                    FheStrLength::Clear(_) => FheStrLength::Clear(1),
                    _ => FheStrLength::Encrypted(
                        self.integer_key
                            .scalar_ne_parallelized(&s.content[s.content.len() - 1 - i].0, 0),
                    ),
                },
                padding: match s.len() {
                    FheStrLength::Clear(_) => Padding::None,
                    _ => Padding::Final,
                },
            });
        }

        // Push last part
        parts.push(FheString {
            content: s.content[..(s.content.len() + 2 - maximum_number_of_parts)].to_vec(),
            length: FheStrLength::Encrypted(
                self.sub_scalar_to_length(s.len(), (maximum_number_of_parts - 2) as u8),
            ),
            padding: s.padding,
        });

        FheSplit {
            parts: parts,
            number_parts: self.integer_key.scalar_min_parallelized(
                &self.add_length_to_radix(&self.create_n(2), s.len()),
                n as u32,
            ),
            current_index: 0,
        }
    }

    pub fn rsplit_encrypted_n_empty_pattern(&self, n: &RadixCiphertext, s: &FheString) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.integer_key.scalar_gt_parallelized(n, 0); // The result has at least 1 part as long as n>0
        let mut found = zero.clone();

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        //let empty_pattern = self.is_empty_encrypted(&pattern);
        // let decrement_search_from = self.integer_key.cmux_parallelized(
        //     &empty_pattern,
        //     &zero.clone(),
        //     &self.sub_scalar_to_length(&pattern.length, 1),
        // );

        for i in 0..maximum_number_of_parts {
            // let start_pattern: RadixCiphertext;
            // (found, start_pattern) =
            //         self.rfind_from_final_padding_allow_empty_pattern(s, pattern, &end_part);

            let in_range_n = self.integer_key.scalar_gt_parallelized(n, (i + 1) as u64);

            // Increment `number_parts` is the pattern found and in range, i.e., i < n-1
            //let found_in_range = self.integer_key.bitand_parallelized(&found, &in_range_n);
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &in_range_n);

            // The new part starts at the end of the pattern if it is found in range, at zero
            // otherwise
            let start_part = self.integer_key.cmux_parallelized(
                &in_range_n,
                &self.integer_key.scalar_sub_parallelized(&end_part, 1),
                &zero,
            );
            // let start_part = self.integer_key.cmux_parallelized(
            //     &found_in_range,
            //     &self.add_length_to_radix(&start_pattern, &pattern.length),
            //     &zero,
            // );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));

            end_part = start_part;
            // self
            // .integer_key
            // .cmux_parallelized(&in_range_n, &start_part, &zero);
        }

        let number_parts_rsplit_empty_pattern = &self.add_length_scalar(&s.length, 2);
        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &self
                .integer_key
                .le_parallelized(&number_parts_rsplit_empty_pattern, &n),
            &number_parts_rsplit_empty_pattern,
            &number_parts,
        );
        // number_parts = self.integer_key.cmux_parallelized(
        //     &self.integer_key.bitand_parallelized(
        //         &empty_pattern,
        //         &self
        //             .integer_key
        //             .le_parallelized(&number_parts_rsplit_empty_pattern, &n),
        //     ),
        //     &number_parts_rsplit_empty_pattern,
        //     &number_parts,
        // );

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_clear_n_clear_string_final_padding(
        &self,
        n: usize,
        s: &FheString,
        pattern: &str,
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
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        //        let empty_pattern = self.is_empty_encrypted(&pattern);
        let decrement_search_from = pattern.len() - 1;
        // self.integer_key.cmux_parallelized(
        //     &empty_pattern,
        //     &zero.clone(),
        //     &self.sub_scalar_to_length(&pattern.length, 1),
        // );

        for i in 0..maximum_number_of_parts_or_n {
            let start_pattern: RadixCiphertext;

            if i > 0 {
                let search_from = self.integer_key.cmux_parallelized(
                    &self
                        .integer_key
                        .scalar_ge_parallelized(&end_part, decrement_search_from as u32),
                    &self
                        .integer_key
                        .scalar_sub_parallelized(&end_part, decrement_search_from as u32),
                    &zero.clone(),
                );
                (found, start_pattern) =
                    self.rfind_clear_from_final_padding(s, pattern, &search_from);
            } else {
                (found, start_pattern) = self.rfind_clear_from_final_padding(s, pattern, &end_part);
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
                    &self
                        .integer_key
                        .scalar_add_parallelized(&start_pattern, pattern.len() as u32),
                    &zero,
                );

                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                end_part = self
                    .integer_key
                    .cmux_parallelized(&found, &start_pattern, &zero);
            }
        }

        //        let number_parts_rsplit_empty_pattern = &self.add_length_scalar(&s.length, 2);
        // Count parts when the pattern is empty
        // number_parts = self.integer_key.cmux_parallelized(
        //     &self.integer_key.bitand_parallelized(
        //         &empty_pattern,
        //         &self
        //             .integer_key
        //             .scalar_le_parallelized(&number_parts_rsplit_empty_pattern, n as u64),
        //     ),
        //     &number_parts_rsplit_empty_pattern,
        //     &number_parts,
        // );

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_encrypted_n_char_final_padding(
        &self,
        n: &RadixCiphertext,
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
        let mut number_parts = self.integer_key.scalar_gt_parallelized(n, 0); // The result has at least 1 part as long as n>0
        let mut found = zero.clone();

        // `end_part` holds the index of the end of the current part.
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        // let empty_pattern = self.is_empty_encrypted(&pattern);
        //let decrement_search_from = pattern.len() -1;
        // let decrement_search_from = self.integer_key.cmux_parallelized(
        //     &empty_pattern,
        //     &zero.clone(),
        //     &self.sub_scalar_to_length(&pattern.length, 1),
        // );

        for i in 0..maximum_number_of_parts {
            let start_pattern: RadixCiphertext;
            (found, start_pattern) = self.rfind_char_from_final_padding(s, pattern, &end_part);

            let in_range_n = self.integer_key.scalar_gt_parallelized(n, (i + 1) as u64);

            // Increment `number_parts` is the pattern found and in range, i.e., i < n-1
            let found_in_range = self.integer_key.bitand_parallelized(&found, &in_range_n);
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &found_in_range);

            // The new part starts at the end of the pattern if it is found in range, at zero
            // otherwise
            let start_part = self.integer_key.cmux_parallelized(
                &found_in_range,
                &self.integer_key.scalar_add_parallelized(&start_pattern, 1),
                &zero,
            );

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));

            end_part = self
                .integer_key
                .cmux_parallelized(&found_in_range, &start_pattern, &zero);
        }

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn rsplit_clear_n_char_final_padding(
        &self,
        n: usize,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
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
        let mut end_part = self.add_length_to_radix(&self.create_n(1), &s.length);
        //        let empty_pattern = self.is_empty_encrypted(&pattern);
        //        let decrement_search_from = pattern.len() -1;
        // self.integer_key.cmux_parallelized(
        //     &empty_pattern,
        //     &zero.clone(),
        //     &self.sub_scalar_to_length(&pattern.length, 1),
        // );

        for i in 0..maximum_number_of_parts_or_n {
            let start_pattern: RadixCiphertext;
            (found, start_pattern) = self.rfind_char_from_final_padding(s, pattern, &end_part);

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
                    &self.integer_key.scalar_add_parallelized(&start_pattern, 1),
                    &zero,
                );

                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                end_part = self
                    .integer_key
                    .cmux_parallelized(&found, &start_pattern, &zero);
            }
        }

        //        let number_parts_rsplit_empty_pattern = &self.add_length_scalar(&s.length, 2);
        // Count parts when the pattern is empty
        // number_parts = self.integer_key.cmux_parallelized(
        //     &self.integer_key.bitand_parallelized(
        //         &empty_pattern,
        //         &self
        //             .integer_key
        //             .scalar_le_parallelized(&number_parts_rsplit_empty_pattern, n as u64),
        //     ),
        //     &number_parts_rsplit_empty_pattern,
        //     &number_parts,
        // );

        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_test, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{
        compare_result, test_fhe_split_char_pattern, test_fhe_split_string_pattern,
        test_splitn_char_pattern, test_splitn_string_pattern,
    };
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    // test_splitn_string_pattern!(rsplitn, 0, "", "");
    // test_splitn_string_pattern!(rsplitn, 1, "", "");
    // test_splitn_string_pattern!(rsplitn, 2, "", "");
    // test_splitn_string_pattern!(rsplitn, 3, "", "");
    // test_splitn_string_pattern!(rsplitn, 0, "", "ab");
    // test_splitn_string_pattern!(rsplitn, 1, "", "ab");
    // test_splitn_string_pattern!(rsplitn, 2, "", "ab");
    // test_splitn_string_pattern!(rsplitn, 3, "", "ab");
    // test_splitn_string_pattern!(rsplitn, 0, "abc", "ab");
    // test_splitn_string_pattern!(rsplitn, 1, "abc", "ab");
    // test_splitn_string_pattern!(rsplitn, 2, "abc", "ab");
    // test_splitn_string_pattern!(rsplitn, 3, "abc", "ab");
    test_splitn_string_pattern!(rsplitn, 0, "aaaaa", "aa");
    test_splitn_string_pattern!(rsplitn, 1, "aaaaa", "aa");
    test_splitn_string_pattern!(rsplitn, 2, "aaaaa", "aa");
    test_splitn_string_pattern!(rsplitn, 4, "aaaaa", "aa");
    test_splitn_string_pattern!(rsplitn, 5, "aaaaa", "aa");
    // test_splitn_string_pattern!(rsplitn, 0, "acbc", "");
    // test_splitn_string_pattern!(rsplitn, 1, "acbc", "");
    // test_splitn_string_pattern!(rsplitn, 2, "acbc", "");
    // test_splitn_string_pattern!(rsplitn, 3, "acbc", "");
    // test_splitn_string_pattern!(rsplitn, 4, "acbc", "");
    // test_splitn_string_pattern!(rsplitn, 5, "acbc", "");
    // test_splitn_string_pattern!(rsplitn, 6, "acbc", "");
    test_splitn_char_pattern!(rsplitn, 0, "ccc", 'c');
    test_splitn_char_pattern!(rsplitn, 1, "ccc", 'c');
    test_splitn_char_pattern!(rsplitn, 2, "ccc", 'c');
    test_splitn_char_pattern!(rsplitn, 3, "ccc", 'c');
    test_splitn_char_pattern!(rsplitn, 4, "ccc", 'c');
    test_splitn_char_pattern!(rsplitn, 5, "ccc", 'c');
    // test_splitn_char_pattern!(rsplitn, 0, "", 'c');
    // test_splitn_char_pattern!(rsplitn, 1, "a", 'c');
    // test_splitn_char_pattern!(rsplitn, 2, "c", 'c');
    // test_splitn_char_pattern!(rsplitn, 3, "ab", 'c');
}
