use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

impl StringServerKey {
    pub fn split_inclusive(&self, s: &FheString, pattern: &impl FhePattern) -> FheSplit {
        pattern.split_inclusive_string(self, s)
    }
    pub fn split_inclusive_encrypted(&self, s: &FheString, pattern: &FheString) -> FheSplit {
        match &pattern.length {
            ClearOrEncrypted::Clear(0) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_terminator_empty_pattern(s1, s2)
            }),
            ClearOrEncrypted::Clear(_) => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_inclusive_encrypted_final_padding(s1, s2)
            }),
            _ => self.padding_pair_dispatch(s, pattern, |s1, s2| {
                self.split_inclusive_encrypted_final_padding_allow_empty_pattern(s1, s2)
            }),
        }
    }

    pub fn split_inclusive_clear(&self, s: &FheString, pattern: &str) -> FheSplit {
        match s.padding {
            _ if pattern.is_empty() => self
                .padding_pair_dispatch(s, s, |s1, s2| self.split_terminator_empty_pattern(s1, s2)),
            Padding::None | Padding::Final => self.split_inclusive_clear_final_padding(s, pattern),
            _ => self.split_inclusive_clear_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn split_inclusive_char(&self, s: &FheString, pattern: &impl FheCharPattern) -> FheSplit {
        match s.padding {
            Padding::None | Padding::Final => self.split_inclusive_char_final_padding(s, pattern),
            _ => self.split_inclusive_char_final_padding(&self.push_padding_to_end(s), pattern),
        }
    }

    pub fn split_inclusive_encrypted_final_padding(
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
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part if s not empty.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let mut trailing_empty_string = self.create_false();

        for _ in 0..maximum_number_of_parts {
            let (found, start_pattern) = self.find_from_final_padding(s, pattern, &start_part);
            let end_part = self.add_length_to_radix(&start_pattern, &pattern.length);
            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = end_part;
            trailing_empty_string =
                self.new_trailing_empty_string(&s.length, &trailing_empty_string, &start_part);
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_inclusive_encrypted_final_padding_allow_empty_pattern(
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
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part is s not empty.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let empty_pattern = self.is_empty_encrypted(pattern);
        let mut trailing_empty_string = self.create_false();
        for n in 0..maximum_number_of_parts {
            let found: BooleanBlock;
            let start_pattern: RadixCiphertext;
            if n >= 1 {
                // When the patern is empty, the search must start at `start_part` plus 1.
                (found, start_pattern) = self.find_from_final_padding_allow_empty_pattern(
                    s,
                    pattern,
                    &self
                        .integer_key
                        .add_parallelized(&start_part, &self.bool_to_radix(&empty_pattern)),
                );
            } else {
                (found, start_pattern) =
                    self.find_from_final_padding_allow_empty_pattern(s, pattern, &start_part);
            }

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));
            let end_part = self.add_length_to_radix(&start_pattern, &pattern.length);
            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = end_part;
            trailing_empty_string =
                self.new_trailing_empty_string(&s.length, &trailing_empty_string, &start_part);
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
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

    pub fn split_inclusive_clear_final_padding(&self, s: &FheString, pattern: &str) -> FheSplit {
        // Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length / pattern.len() + 1,
            _ => s.content.len() / pattern.len() + 1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let zero = self.create_zero();
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part a long as s not empty.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let mut trailing_empty_string = self.create_false();
        for _ in 0..maximum_number_of_parts {
            let (found, start_pattern) =
                self.find_clear_from_final_padding(s, pattern, &start_part);

            let end_part = self
                .integer_key
                .scalar_add_parallelized(&start_pattern, pattern.len() as u64);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = end_part;
            trailing_empty_string =
                self.new_trailing_empty_string(&s.length, &trailing_empty_string, &start_part);
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn split_inclusive_char_final_padding(
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
        let mut number_parts = self.bool_to_radix(&self.is_not_empty_encrypted(s)); // The result has at least 1 part as long as s is not empty.

        // `start_part` holds the index of the beginning of the current part.
        let mut start_part = zero.clone();
        let mut trailing_empty_string = self.create_false();
        for _ in 0..maximum_number_of_parts {
            let (found, start_pattern) = self.find_char_from_final_padding(s, pattern, &start_part);

            let end_part = self.integer_key.scalar_add_parallelized(&start_pattern, 1);

            // Increment `number_parts` if the pattern is found.
            self.integer_key
                .add_assign_parallelized(&mut number_parts, &self.bool_to_radix(&found));

            parts.push(self.substring_encrypted_final_padding(s, &start_part, &end_part));
            start_part = end_part;
            trailing_empty_string =
                self.new_trailing_empty_string(&s.length, &trailing_empty_string, &start_part);
        }
        self.integer_key.sub_assign_parallelized(
            &mut number_parts,
            &self.bool_to_radix(&trailing_empty_string),
        );
        FheSplit {
            parts,
            number_parts,
            current_index: 0,
        }
    }

    pub fn new_trailing_empty_string(
        &self,
        s_length: &FheStrLength,
        previous_trailing_empty_string: &BooleanBlock,
        start_part: &RadixCiphertext,
    ) -> BooleanBlock {
        match s_length {
            FheStrLength::Clear(clear_length) => self.integer_key.boolean_bitor(
                previous_trailing_empty_string,
                &self
                    .integer_key
                    .scalar_eq_parallelized(start_part, *clear_length as u64),
            ),
            FheStrLength::Encrypted(encrypted_length) => self.integer_key.boolean_bitor(
                previous_trailing_empty_string,
                &self
                    .integer_key
                    .eq_parallelized(start_part, encrypted_length),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys_test;
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    // test_fhe_split_string_pattern!(split_inclusive, "", "");
    // test_fhe_split_string_pattern!(split_inclusive, "", "ab");
    // test_fhe_split_string_pattern!(split_inclusive, "acbc", "c");

    // test_fhe_split_char_pattern!(split_inclusive, "", 'a');
    // test_fhe_split_char_pattern!(split_inclusive, "a", 'a');
    // test_fhe_split_char_pattern!(split_inclusive, "acbc", 'c');
    // test_fhe_split_char_pattern!(split_inclusive, "cccc", 'c');
    // test_fhe_split_char_pattern!(split_inclusive, "cabd", 'a');
    // test_fhe_split_char_pattern!(split_inclusive, "acb", 'c');
}
