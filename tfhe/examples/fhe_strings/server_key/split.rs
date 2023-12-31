use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString, Padding};
use crate::integer_arg::FheIntegerArg;
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

pub type ResultFheString = (BooleanBlock, FheString);

/// A structure to store results of split functions on encrypted strings. The parts obtained by
/// splitting are stored as the first number_parts encrypted string in the vector parts. Number of
/// parts is an encrypted integer. The elements in parts after number_parts are not assured to be
/// empty string and should be ignored.
pub struct FheSplit {
    pub parts: Vec<FheString>,
    pub number_parts: RadixCiphertext,
    pub current_index: usize,
}

impl StringServerKey {
    /// Splits the string s at each occurence of pattern.
    /// # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aba").unwrap();
    /// let pattern = client_key.encrypt_str("a").unwrap();
    /// let fhe_result = server_key.split(&encrypted_str, &pattern);
    /// let std_result = "aba".to_string().split("a");
    /// let clear_len = client_key.decrypt_integer(&fhe_result.number_parts);
    /// let std_split: Vec<String> = std_result.map(|s| String::from(s)).collect();
    /// let clear_split: Vec<String> = $fhe_result.parts[..(clear_len as usize)]
    ///     .iter()
    ///     .map(|s| client_key.decrypt_string(s).unwrap())
    ///     .collect();
    /// assert_eq!(clear_split, std_split);
    /// ```
    pub fn split(&self, s: &FheString, pattern: &impl FhePattern) -> FheSplit {
        pattern.split_string(self, s)
    }

    /// Splits the string s at each occurence of pattern (encrypted string).
    ///  The complexity is O(length(s)^2*length(pattern)) FHE operations.  Add a
    /// O(pattern.content.len()^2) if the patterns has padding worst than final. Add a
    /// O(haystack.content.len()^2) if haystack has padding worst than final.
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

    /// Splits the string s at each occurence of pattern (clear string).
    pub fn split_clear(&self, s: &FheString, pattern: &str) -> FheSplit {
        match s.padding {
            _ if pattern.is_empty() => {
                self.padding_pair_dispatch(s, s, |s1, s2| self.split_empty_pattern(s1, s2))
            }
            Padding::None | Padding::Final => self.split_clear_final_padding(s, pattern),
            _ => self.split_clear_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    /// Splits the string s at each occurence of pattern (clear or encrypted character).
    pub fn split_char(&self, s: &FheString, pattern: &impl FheCharPattern) -> FheSplit {
        match s.padding {
            Padding::None | Padding::Final => self.split_char_final_padding(s, pattern),
            _ => self.split_char_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    /// Splits n times the string s at each occurence of pattern.
    /// # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aba").unwrap();
    /// let pattern = client_key.encrypt_str("a").unwrap();
    /// let n = client_key.encrypt_integer(1 as u32);
    /// let fhe_result = server_key.splitn(&encrypted_str, &n, &pattern);
    /// let clear_string: String = "aba".to_string();
    /// let std_result = clear_string.splitn(1, "a");
    /// let clear_len = client_key.decrypt_integer(&fhe_result.number_parts);
    /// let std_split: Vec<String> = std_result.map(|s| String::from(s)).collect();
    /// let clear_split: Vec<String> = fhe_result.parts[..(clear_len as usize)]
    ///     .iter()
    ///     .map(|s| client_key.decrypt_string(s).unwrap())
    ///     .collect();
    /// assert_eq!(clear_split, std_split);
    /// ```
    pub fn splitn(
        &self,
        s: &FheString,
        n: &impl FheIntegerArg,
        pattern: &impl FhePattern,
    ) -> FheSplit {
        pattern.splitn_string(self, n, s)
    }

    // Following functions cover various possibility of encryption for arguments of splitn.
    pub fn splitn_encrypted_string(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        n.splitn_encrypted_string(self, s, pattern)
    }

    pub fn splitn_clear_string(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        n.splitn_clear_string_pattern(self, s, pattern)
    }

    pub fn splitn_char(
        &self,
        n: &impl FheIntegerArg,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        n.splitn_char_pattern(self, s, pattern)
    }

    pub fn split_clear_n_encrypted_string(
        &self,
        n: usize,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        self.padding_pair_dispatch(s, pattern, |s1, s2| {
            self.split_clear_n_encrypted_final_padding_allow_empty_pattern(n, s1, s2)
        })
    }

    pub fn split_encrypted_n_encrypted_string(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        self.padding_pair_dispatch(s, pattern, |s1, s2| {
            self.split_encrypted_n_encrypted_final_padding_allow_empty_pattern(n, s1, s2)
        })
    }

    pub fn split_clear_n_clear_string(&self, n: usize, s: &FheString, pattern: &str) -> FheSplit {
        if pattern.is_empty() {
            return self.padding_dispatch(s, |s1| self.split_clear_n_empty_pattern(n, s1));
        }
        self.padding_dispatch(s, |s1| {
            self.split_clear_n_clear_string_final_padding(n, s1, pattern)
        })
    }

    pub fn split_encrypted_n_clear_string(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        if pattern.is_empty() {
            return self.padding_dispatch(s, |s1| self.split_encrypted_n_empty_pattern(n, s1));
        }
        self.padding_dispatch(s, |s1| {
            self.split_encrypted_n_clear_string_final_padding(n, s1, pattern)
        })
    }

    pub fn split_encrypted_n_char(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        self.padding_dispatch(s, |s1| {
            self.split_encrypted_n_char_final_padding(n, s1, pattern)
        })
    }

    pub fn split_clear_n_char(
        &self,
        n: usize,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        self.padding_dispatch(s, |s1| {
            self.split_clear_n_char_final_padding(n, s1, pattern)
        })
    }

    /// Splits n times the string s at each occurence of the empty pattern, same behaviour as splitn
    /// for clear strings form the standard library.
    pub fn split_encrypted_n_empty_pattern(&self, n: &RadixCiphertext, s: &FheString) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut start_part = zero.clone();
        let mut end_part = self.integer_key.cmux_parallelized(
            &self.integer_key.scalar_eq_parallelized(n, 1),
            &self.add_length_to_radix(&zero, s.len()),
            &zero,
        );
        parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));

        for i in 1..maximum_number_of_parts {
            let out_of_range = self.integer_key.scalar_le_parallelized(n, (i + 1) as u64);
            end_part = self.integer_key.cmux_parallelized(
                &out_of_range,
                &self.add_length_to_radix(&self.create_zero(), &s.length),
                &self.integer_key.scalar_add_parallelized(&start_part, 1),
            );
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = end_part;
        }
        let number_parts_for_split_with_empty_pattern =
            self.add_length_to_radix(&self.create_n(2), &s.length);
        let number_parts = self.integer_key.cmux_parallelized(
            &self
                .integer_key
                .ge_parallelized(n, &number_parts_for_split_with_empty_pattern),
            &number_parts_for_split_with_empty_pattern,
            n,
        );
        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_clear_n_empty_pattern(&self, n: usize, s: &FheString) -> FheSplit {
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

        //let mut number_parts = self.bool_to_radix(&self.integer_key.scalar_gt_parallelized(n,
        // 0));

        if n == 1 {
            parts.push(s.clone());
            return FheSplit {
                parts,
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
                content: vec![s.content[i].clone()],
                length: match s.len() {
                    FheStrLength::Clear(_) => FheStrLength::Clear(1),
                    _ => FheStrLength::Encrypted(self.bool_to_radix(
                        &self.integer_key.scalar_ne_parallelized(&s.content[i].0, 0),
                    )),
                },
                padding: match s.len() {
                    FheStrLength::Clear(_) => Padding::None,
                    _ => Padding::Final,
                },
            });
        }

        // Push last part
        parts.push(FheString {
            content: s.content[maximum_number_of_parts - 2..].to_vec(),
            length: FheStrLength::Encrypted(
                self.sub_scalar_to_length(s.len(), (maximum_number_of_parts - 2) as u8),
            ),
            padding: s.padding,
        });

        FheSplit {
            parts,
            number_parts: self.integer_key.scalar_min_parallelized(
                &self.add_length_to_radix(&self.create_n(2), s.len()),
                n as u32,
            ),
            current_index: 0,
        }
    }

    /// Splits the string s at each occurence of the empty pattern, same behaviour as splitn for
    /// clear strings form the standard library.
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

    pub fn split_char_final_padding(
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

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();

        for _ in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_char_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.integer_key.scalar_add_parallelized(&end_part, 1);
        }
        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_clear_final_padding(&self, s: &FheString, pattern: &str) -> FheSplit {
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

        for _ in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_clear_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self
                .integer_key
                .scalar_add_parallelized(&end_part, pattern.len() as u64);
        }
        FheSplit {
            parts,
            number_parts,
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

        for _ in 0..maximum_number_of_parts {
            let (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.add_length_to_radix(&end_part, &pattern.length);
        }
        FheSplit {
            parts,
            number_parts,
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
                parts.push(self.substring_from_encrypted_final_padding(s, &start_part));
            } else {
                // Increment `number_parts` if the pattern is found.
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                start_part = self.add_length_to_radix(&end_part, &pattern.length);
            }
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    /// Splits the string s at each occurence of the pattern. It assumes that both s and pattern
    /// have at worst final padding. It works even if pattern is the empty string eventually padded.
    /// The algorithm relies on consecutive applications of
    /// find_from_final_padding_allow_empty_pattern. The complexity is
    /// O(length(s)^2*length(pattern)) FHE operations.  Add a O(pattern.content.len()^2) if the
    /// patterns has padding worst than final. Add a O(haystack.content.len()^2) if haystack has
    /// padding worst than final.
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
        let empty_pattern = self.is_empty_encrypted(pattern);

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

    pub fn add_length_scalar(&self, length: &FheStrLength, n: u8) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n(*clear_length as u8 + n),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_add_parallelized(encrypted_length, n),
        }
    }

    /// Call the function F with s1 and s2 after pushing back their padding zeros if necessary.
    pub fn padding_pair_dispatch<F>(&self, s1: &FheString, s2: &FheString, f: F) -> FheSplit
    where
        F: Fn(&FheString, &FheString) -> FheSplit,
    {
        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => f(s1, s2),
            (Padding::None | Padding::Final, _) => f(s1, &self.push_padding_to_end(s2)),
            (_, Padding::None | Padding::Final) => f(&self.push_padding_to_end(s1), s2),
            _ => f(&self.push_padding_to_end(s1), &self.push_padding_to_end(s2)),
        }
    }

    /// Call the function F with s after pushing back its padding zeros.
    pub fn padding_dispatch<F>(&self, s: &FheString, f: F) -> FheSplit
    where
        F: Fn(&FheString) -> FheSplit,
    {
        match s.padding {
            Padding::None | Padding::Final => f(s),
            _ => f(&self.push_padding_to_end(s)),
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
        let mut number_parts = match n {
            0 => self.create_zero(),
            _ => self.create_n(1), // The result has at least 1 part as long as n > 0.
        };
        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let empty_pattern = self.is_empty_encrypted(pattern);

        for i in 0..maximum_number_of_parts_or_n {
            let found: BooleanBlock;
            let end_part: RadixCiphertext;
            if i >= 1 {
                // When the patern is empty, the search must start at `start_part` plus 1.
                (found, end_part) = self.find_from_final_padding(
                    s,
                    pattern,
                    &self
                        .integer_key
                        .add_parallelized(&start_part, &self.bool_to_radix(&empty_pattern)),
                );
            } else {
                (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);
            }

            if i == n - 1 {
                parts.push(self.substring_from_encrypted_final_padding(s, &start_part));
            } else {
                // Increment `number_parts` if the pattern is found.
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
                parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
                start_part = self.add_length_to_radix(&end_part, &pattern.length);
            }
        }
        let number_parts_split_empty_pattern = self.add_length_scalar(&s.length, 2);
        // Count parts when the pattern is empty
        number_parts = self.integer_key.cmux_parallelized(
            &self.integer_key.boolean_bitand(
                &empty_pattern,
                &self
                    .integer_key
                    .scalar_le_parallelized(&number_parts_split_empty_pattern, n as u64),
            ),
            &number_parts_split_empty_pattern,
            &number_parts,
        );

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_encrypted_n_encrypted_final_padding_allow_empty_pattern(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 2,
            _ => s.content.len() + 2,
        };
        //        let maximum_number_of_parts_or_n = self.integer(n, maximum_number_of_parts);

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.integer_key.scalar_gt_parallelized(n, 0));
        // let mut number_parts = match n {
        //     0 => self.create_zero(),
        //     _ => self.create_n(1), // The result has at least 1 part as long as n > 0.
        // };
        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let empty_pattern = self.is_empty_encrypted(pattern);

        for i in 0..maximum_number_of_parts {
            let mut found: BooleanBlock;
            let mut end_part: RadixCiphertext;
            if i >= 1 {
                // When the patern is empty, the search must start at `start_part` plus 1.
                (found, end_part) = self.find_from_final_padding(
                    s,
                    pattern,
                    &self
                        .integer_key
                        .add_parallelized(&start_part, &self.bool_to_radix(&empty_pattern)),
                );
            } else {
                (found, end_part) = self.find_from_final_padding(s, pattern, &start_part);
            }
            let out_of_range = self.integer_key.scalar_le_parallelized(n, (i + 1) as u64);

            end_part = self.integer_key.cmux_parallelized(
                &out_of_range,
                &self.add_length_to_radix(&self.create_zero(), &s.length),
                &end_part,
            );

            found = self.radix_to_bool(&self.integer_key.cmux_parallelized(
                &out_of_range,
                &zero.clone(),
                &self.bool_to_radix(&found),
            ));
            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.add_length_to_radix(&end_part, &pattern.length);
        }
        let number_parts_for_split_with_empty_pattern =
            self.add_length_to_radix(&self.create_n(2), &s.length);
        number_parts = self.integer_key.cmux_parallelized(
            &self.integer_key.boolean_bitand(
                &empty_pattern,
                &self
                    .integer_key
                    .ge_parallelized(n, &number_parts_for_split_with_empty_pattern),
            ),
            &number_parts_for_split_with_empty_pattern,
            &number_parts,
        );

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_encrypted_n_clear_string_final_padding(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length / pattern.len() + 1,
            _ => s.content.len() / pattern.len() + 1,
        };

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.integer_key.scalar_gt_parallelized(n, 0));

        let mut start_part = zero.clone();

        for i in 0..maximum_number_of_parts {
            let (mut found, mut end_part) =
                self.find_clear_from_final_padding(s, pattern, &start_part);
            let out_of_range = self.integer_key.scalar_le_parallelized(n, (i + 1) as u64);

            end_part = self.integer_key.cmux_parallelized(
                &out_of_range,
                &self.add_length_to_radix(&self.create_zero(), &s.length),
                &end_part,
            );
            found = self.radix_to_bool(&self.integer_key.cmux_parallelized(
                &out_of_range,
                &zero.clone(),
                &self.bool_to_radix(&found),
            ));
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self
                .integer_key
                .scalar_add_parallelized(&end_part, pattern.len() as u32);
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_clear_n_clear_string_final_padding(
        &self,
        n: usize,
        s: &FheString,
        pattern: &str,
    ) -> FheSplit {
        let maximum_number_of_parts_split = match &s.length {
            ClearOrEncrypted::Clear(length) => *length / pattern.len() + 1,
            _ => s.content.len() / pattern.len() + 1,
        };
        let maximum_number_of_parts = std::cmp::min(maximum_number_of_parts_split, n);
        if maximum_number_of_parts == 0 {
            return FheSplit {
                parts: vec![],
                number_parts: self.create_zero(),
                current_index: 0,
            };
        }

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1);

        let mut start_part = zero.clone();

        for i in 0..maximum_number_of_parts {
            let found: BooleanBlock;
            let end_part: RadixCiphertext;
            if n <= i + 1 {
                end_part = self.add_length_to_radix(&self.create_zero(), &s.length);
                //found = fhe_false.clone();
            } else {
                (found, end_part) = self.find_clear_from_final_padding(s, pattern, &start_part);
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
            }
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self
                .integer_key
                .scalar_add_parallelized(&end_part, pattern.len() as u32);
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_clear_n_char_final_padding(
        &self,
        n: usize,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        let maximum_number_of_parts_split = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
        };
        let maximum_number_of_parts = std::cmp::min(maximum_number_of_parts_split, n);
        if maximum_number_of_parts == 0 {
            return FheSplit {
                parts: vec![],
                number_parts: self.create_zero(),
                current_index: 0,
            };
        }

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.create_n(1);

        let mut start_part = zero.clone();

        for i in 0..maximum_number_of_parts {
            let found: BooleanBlock;
            let end_part: RadixCiphertext;

            if n <= i + 1 {
                end_part = self.add_length_to_radix(&self.create_zero(), &s.length);
                //found = fhe_false.clone();
            } else {
                (found, end_part) = self.find_char_from_final_padding(s, pattern, &start_part);
                self.integer_key
                    .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
            }
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.integer_key.scalar_add_parallelized(&end_part, 1);
        }

        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_encrypted_n_char_final_padding(
        &self,
        n: &RadixCiphertext,
        s: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() + 1,
        };

        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.integer_key.scalar_gt_parallelized(n, 0));

        let mut start_part = zero.clone();

        for i in 0..maximum_number_of_parts {
            let (mut found, mut end_part) =
                self.find_char_from_final_padding(s, pattern, &start_part);
            let out_of_range = self.integer_key.scalar_le_parallelized(n, (i + 1) as u64);

            end_part = self.integer_key.cmux_parallelized(
                &out_of_range,
                &self.add_length_to_radix(&self.create_zero(), &s.length),
                &end_part,
            );

            found = self.radix_to_bool(&self.integer_key.cmux_parallelized(
                &out_of_range,
                &zero.clone(),
                &self.bool_to_radix(&found),
            ));
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = self.integer_key.scalar_add_parallelized(&end_part, 1);
        }

        FheSplit {
            parts,
            number_parts,
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

    pub fn sub_scalar_to_length(&self, length: &FheStrLength, n: u8) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_sub_parallelized(encrypted_length, n),
            ClearOrEncrypted::Clear(clear_length) if *clear_length as u8 >= n => {
                self.create_n(*clear_length as u8 - n)
            }
            _ => self.create_zero(),
        }
    }

    pub fn sub_length_to_radix(
        &self,
        end_part: &RadixCiphertext,
        pattern_length: &FheStrLength,
    ) -> RadixCiphertext {
        match pattern_length {
            ClearOrEncrypted::Encrypted(encrypted_length) => self.integer_key.cmux_parallelized(
                &self.integer_key.ge_parallelized(end_part, encrypted_length),
                &self
                    .integer_key
                    .sub_parallelized(end_part, encrypted_length),
                &self.create_zero(),
            ),
            ClearOrEncrypted::Clear(clear_length) => self.integer_key.cmux_parallelized(
                &self
                    .integer_key
                    .scalar_ge_parallelized(end_part, *clear_length as u64),
                &self
                    .integer_key
                    .scalar_sub_parallelized(end_part, *clear_length as u64),
                &self.create_zero(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys_test;
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_splitn_string_pattern};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn doctest_split() {
        let (client_key, server_key) = gen_keys_test();
        let encrypted_str = client_key.encrypt_str("aba").unwrap();
        let pattern = client_key.encrypt_str("a").unwrap();
        let fhe_result = server_key.split(&encrypted_str, &pattern);
        let clear_string: String = "aba".to_string();
        let std_result = clear_string.split("a");
        let clear_len = client_key.decrypt_integer(&fhe_result.number_parts);
        let std_split: Vec<String> = std_result.map(|s| String::from(s)).collect();
        let clear_split: Vec<String> = fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| client_key.decrypt_string(s).unwrap())
            .collect();
        assert_eq!(clear_split, std_split);
    }

    #[test]
    fn doctest_splitn() {
        let (client_key, server_key) = gen_keys_test();
        let encrypted_str = client_key.encrypt_str("aba").unwrap();
        let pattern = client_key.encrypt_str("a").unwrap();
        let n = client_key.encrypt_integer(1 as u32);
        let fhe_result = server_key.splitn(&encrypted_str, &n, &pattern);
        let clear_string: String = "aba".to_string();
        let std_result = clear_string.splitn(1, "a");
        let clear_len = client_key.decrypt_integer(&fhe_result.number_parts);
        let std_split: Vec<String> = std_result.map(|s| String::from(s)).collect();
        let clear_split: Vec<String> = fhe_result.parts[..(clear_len as usize)]
            .iter()
            .map(|s| client_key.decrypt_string(s).unwrap())
            .collect();
        assert_eq!(clear_split, std_split);
    }
    test_splitn_string_pattern!(splitn, 0, "aaa", "a");
    test_splitn_string_pattern!(splitn, 1, "aaa", "a");
    test_splitn_string_pattern!(splitn, 4, "aaa", "a");
    // test_splitn_string_pattern!(splitn, 3, "", "");
    // test_splitn_string_pattern!(splitn, 0, "", "");
    // test_splitn_string_pattern!(splitn, 1, "", "");
    // test_splitn_string_pattern!(splitn, 2, "", "");
    // test_splitn_string_pattern!(splitn, 3, "", "");
    // test_splitn_string_pattern!(splitn, 0, "", "ab");
    // test_splitn_string_pattern!(splitn, 1, "", "ab");
    // test_splitn_string_pattern!(splitn, 2, "", "ab");
    // test_splitn_string_pattern!(splitn, 3, "", "ab");
    // test_splitn_string_pattern!(splitn, 0, "ab", "ab");
    // test_splitn_string_pattern!(splitn, 1, "ab", "ab");
    // test_splitn_string_pattern!(splitn, 2, "ab", "ab");
    // test_splitn_string_pattern!(splitn, 3, "ab", "ab");
    // test_splitn_string_pattern!(splitn, 0, "abc", "ab");
    // test_splitn_string_pattern!(splitn, 1, "abc", "ab");
    // test_splitn_string_pattern!(splitn, 2, "abc", "ab");
    // test_splitn_string_pattern!(splitn, 3, "abc", "ab");
    // test_splitn_string_pattern!(splitn, 0, "abab", "ab");
    // test_splitn_string_pattern!(splitn, 1, "abab", "ab");
    // test_splitn_string_pattern!(splitn, 2, "abab", "ab");
    // test_splitn_string_pattern!(splitn, 3, "abab", "ab");
    // test_splitn_string_pattern!(splitn, 0, "abcab", "ab");
    // test_splitn_string_pattern!(splitn, 1, "abcab", "ab");
    // test_splitn_string_pattern!(splitn, 2, "abcab", "ab");
    // test_splitn_string_pattern!(splitn, 3, "abcab", "ab");
    // test_splitn_string_pattern!(splitn, 0, "cab", "ab");
    // test_splitn_string_pattern!(splitn, 1, "cab", "ab");
    // test_splitn_string_pattern!(splitn, 2, "cab", "ab");
    // test_splitn_string_pattern!(splitn, 3, "cab", "ab");
    // test_splitn_string_pattern!(splitn, 0, "acbc", "c");
    // test_splitn_string_pattern!(splitn, 1, "acbc", "c");
    // test_splitn_string_pattern!(splitn, 2, "acbc", "c");
    // test_splitn_string_pattern!(splitn, 3, "acbc", "c");
    // test_splitn_string_pattern!(splitn, 4, "acbc", "c");
    // test_splitn_string_pattern!(splitn, 0, "acbc", "");
    // test_splitn_string_pattern!(splitn, 1, "acbc", "");
    // test_splitn_string_pattern!(splitn, 2, "acbc", "");
    // test_splitn_string_pattern!(splitn, 3, "acbc", "");
    // test_splitn_string_pattern!(splitn, 4, "acbc", "");
    // test_splitn_string_pattern!(splitn, 5, "acbc", "");
    // test_splitn_string_pattern!(splitn, 6, "acbc", "");
    // test_splitn_string_pattern!(splitn, 7, "acbc", "");
    // test_splitn_char_pattern!(splitn, 0, "acbc", 'c');
    // test_splitn_char_pattern!(splitn, 1, "acbc", 'c');
    // test_splitn_char_pattern!(splitn, 2, "acbc", 'c');
    // test_splitn_char_pattern!(splitn, 3, "acbc", 'c');
    // test_splitn_char_pattern!(splitn, 4, "acbc", 'c');
    // test_splitn_char_pattern!(splitn, 0, "", 'c');
    // test_splitn_char_pattern!(splitn, 1, "a", 'c');
    // test_splitn_char_pattern!(splitn, 2, "c", 'c');
    // test_splitn_char_pattern!(splitn, 3, "ab", 'c');

    // test_fhe_split_char_pattern!(split, "", 'a');
    // test_fhe_split_char_pattern!(split, "a", 'a');
    // test_fhe_split_char_pattern!(split, "acbc", 'c');
    // test_fhe_split_char_pattern!(split, "cccc", 'c');
    // test_fhe_split_char_pattern!(split, "cabd", 'a');
    // test_fhe_split_char_pattern!(split, "acb", 'c');

    // test_fhe_split_string_pattern!(split, "", "");
    // test_fhe_split_string_pattern!(split, "", "ab");
    // test_fhe_split_string_pattern!(split, "acbc", "c");

    // test_fhe_split_char_pattern!(split, "", 'a');
    // test_fhe_split_char_pattern!(split, "a", 'a');
    // test_fhe_split_char_pattern!(split, "acbc", 'c');
    // test_fhe_split_char_pattern!(split, "cccc", 'c');
    // test_fhe_split_char_pattern!(split, "cabd", 'a');
    // test_fhe_split_char_pattern!(split, "acb", 'c');
    // test_fhe_split_string!(split_clear, "", "");
    // test_fhe_split_string!(split_clear, "", "ab");
    // test_fhe_split_string!(split_clear, "acbc", "c");

    // test_fhe_split_string!(split_char, "", 'a');
    // test_fhe_split_string!(split_char, "a", 'a');
    // test_fhe_split_string!(split_char, "acbc", 'c');
    // test_fhe_split_string!(split_char, "cccc", 'c');
    // test_fhe_split_string!(split_char, "cabd", 'c');
    // test_fhe_split_string!(split_char, "acb", 'c');
}
