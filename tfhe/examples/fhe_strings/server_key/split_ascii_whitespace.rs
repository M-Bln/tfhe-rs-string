use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::integer_arg::FheIntegerArg;
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

pub type ResultFheString = (RadixCiphertext, FheString);

pub struct FheSplit {
    pub parts: Vec<FheString>,
    pub number_parts: RadixCiphertext,
    pub current_index: usize,
}

impl StringServerKey {
    pub fn is_ascii_white_space(&self, c: &FheAsciiChar) -> BooleanBlock {
        let is_tab_feed_return = self.integer_key.boolean_bitand(
            &self.integer_key.scalar_ge_parallelized(&c.0, 9),
            &self.integer_key.scalar_le_parallelized(&c.0, 13),
        );
        let is_space = self.integer_key.scalar_eq_parallelized(&c.0, 32);
        self.integer_key
            .boolean_bitor(&is_tab_feed_return, &is_space)
    }

    pub fn is_not_ascii_white_space(&self, c: &FheAsciiChar) -> BooleanBlock {
        let is_not_tab_feed_return = self.integer_key.boolean_bitor(
            &self.integer_key.scalar_lt_parallelized(&c.0, 9),
            &self.integer_key.scalar_gt_parallelized(&c.0, 13),
        );
        let is_not_space = self.integer_key.scalar_ne_parallelized(&c.0, 32);
        self.integer_key
            .boolean_bitand(&is_not_tab_feed_return, &is_not_space)
    }

    pub fn index_first_non_white_nor_null(
        &self,
        s: &FheString,
        from: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = self.create_zero();
        let mut found = self.create_false();
        for (i, c) in s.content.iter().enumerate() {
            let in_range = self.integer_key.scalar_le_parallelized(from, i as u32);
            let non_white = self.is_not_ascii_white_space(c);
            let non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
            let content_in_range = self.integer_key.boolean_bitand(
                &self.integer_key.boolean_bitand(&in_range, &non_white),
                &non_null,
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &content_in_range);
            self.integer_key.add_assign_parallelized(
                &mut result,
                &self.bool_to_radix(&self.integer_key.boolean_bitnot(&found)),
            )
        }
        result
    }

    pub fn index_end_chunk(&self, s: &FheString, from: &RadixCiphertext) -> RadixCiphertext {
        let zero = self.create_zero();
        let mut result = zero.clone();
        let mut found = self.create_false();
        for (i, c) in s.content.iter().enumerate() {
            let in_range = self.integer_key.scalar_le_parallelized(from, i as u32);
            let is_white = self.is_ascii_white_space(c);
            //let non_null = self.integer_key.scalar_ne_parallelized(&c.0, 0);
            let is_white_in_range = &self.integer_key.boolean_bitand(&in_range, &is_white);

            // self.integer_key.boolean_bitand(
            // 	&self.integer_key.boolean_bitand(
            // 	    &in_range,
            // 	    &non_white,
            // 	),
            // 	&non_null,
            // );
            self.integer_key
                .boolean_bitor_assign(&mut found, &is_white_in_range);
            self.integer_key.add_assign_parallelized(
                &mut result,
                &self.bool_to_radix(&self.integer_key.boolean_bitnot(&found)),
            );
        }
        result
    }

    pub fn next_non_white_chunk(
        &self,
        s: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let start_chunk = self.index_first_non_white_nor_null(s, from);
        let end_chunk = self.index_end_chunk(s, &start_chunk);
        (start_chunk, end_chunk)
    }

    pub fn old_next_non_white_chunk(
        &self,
        s: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut start_chunk = self.create_zero();
        let mut end_chunk = self.create_zero();
        let mut prev_is_not_content_in_range = self.create_true();
        let mut prev_non_white_and_in_range = self.create_false();
        for (i, c) in s.content.iter().enumerate() {
            let in_range = self.integer_key.scalar_le_parallelized(from, i as u32);
            let non_white = self.is_not_ascii_white_space(c);
            let non_white_and_in_range = self.integer_key.boolean_bitand(&non_white, &in_range);
            let is_content_in_range = self.integer_key.boolean_bitand(
                &non_white_and_in_range,
                &self.integer_key.scalar_ne_parallelized(&c.0, 0),
            );

            let first_content_in_range = self
                .integer_key
                .boolean_bitand(&is_content_in_range, &prev_is_not_content_in_range);

            let end_non_white_in_range = self.integer_key.boolean_bitand(
                &prev_non_white_and_in_range,
                &self.integer_key.boolean_bitnot(&non_white),
            );

            prev_is_not_content_in_range = self.integer_key.boolean_bitnot(&is_content_in_range);
            prev_non_white_and_in_range = non_white_and_in_range;

            start_chunk = self.integer_key.cmux_parallelized(
                &self.integer_key.boolean_bitand(
                    &first_content_in_range,
                    &self.integer_key.scalar_eq_parallelized(&start_chunk, 0),
                ),
                &self.create_n(i as u8),
                &start_chunk,
            );

            end_chunk = self.integer_key.cmux_parallelized(
                &self.integer_key.boolean_bitand(
                    &end_non_white_in_range,
                    &self.integer_key.scalar_eq_parallelized(&end_chunk, 0),
                ),
                &self.create_n(i as u8),
                &end_chunk,
            );
        }
        end_chunk = self.integer_key.cmux_parallelized(
            &self.integer_key.boolean_bitand(
                &prev_non_white_and_in_range,
                &self.integer_key.scalar_eq_parallelized(&end_chunk, 0),
            ),
            &self.create_n(s.content.len() as u8),
            &end_chunk,
        );
        (start_chunk, end_chunk)
    }

    pub fn split_ascii_whitespace(&self, s: &FheString) -> FheSplit {
        let maximum_number_of_parts: usize;
        let zero = self.create_zero();
        match s.len() {
            _ if s.content.is_empty() => {
                return FheSplit {
                    parts: vec![],
                    number_parts: zero,
                    current_index: 0,
                }
            }
            FheStrLength::Clear(0) => {
                return FheSplit {
                    parts: vec![],
                    number_parts: zero,
                    current_index: 0,
                }
            }
            FheStrLength::Clear(clear_length) if *clear_length > 0 => {
                maximum_number_of_parts = *clear_length / 2 + 1;
            }
            _ => {
                maximum_number_of_parts = s.content.len() / 2 + 1;
            }
        }
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);
        let mut number_parts = zero.clone();
        let mut from = zero;
        for _ in 0..maximum_number_of_parts {
            let (start_chunk, end_chunk) = self.next_non_white_chunk(s, &from);
            // Count the chunk one is found (i.e. if it is a non empty range)
            self.integer_key.add_assign_parallelized(
                &mut number_parts,
                &self.bool_to_radix(&self.integer_key.ne_parallelized(&start_chunk, &end_chunk)),
            );

            parts.push(self.content_slice(s, &start_chunk, &end_chunk));
            from = end_chunk;
        }
        FheSplit {
            parts: parts,
            number_parts: number_parts,
            current_index: 0,
        }
    }

    pub fn content_slice(
        &self,
        s: &FheString,
        start: &RadixCiphertext,
        end: &RadixCiphertext,
    ) -> FheString {
        let zero = &self.create_zero();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        for (n, c) in s.content.iter().enumerate() {
            // Check if the index `n` is in the range `start`-`end`.
            let in_range: BooleanBlock = self.integer_key.boolean_bitand(
                &self.integer_key.scalar_le_parallelized(start, n as u64),
                &self.integer_key.scalar_gt_parallelized(end, n as u64),
            );

            // If `n` is in range, take the content of `s` otherwise take a null character.
            let new_char_content: RadixCiphertext =
                self.integer_key.cmux_parallelized(&in_range, &c.0, &zero);
            result_content.push(FheAsciiChar(new_char_content));
        }
        let result_padding = match s.padding {
            Padding::Anywhere => Padding::Anywhere,
            _ => Padding::InitialAndFinal,
        };
        let result_length = match s.padding {
            Padding::Final => self.length_of_slice_encrypted_range(&s.length, start, end),
            _ => self.count_length(&result_content),
        };
        FheString {
            content: result_content,
            padding: result_padding,
            length: result_length,
        }
    }

    pub fn count_length(&self, content: &[FheAsciiChar]) -> FheStrLength {
        let mut result = self.create_zero();
        for c in content {
            self.integer_key.add_assign_parallelized(
                &mut result,
                &self.bool_to_radix(&self.integer_key.scalar_ne_parallelized(&c.0, 0)),
            )
        }
        FheStrLength::Encrypted(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_test, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{
        compare_result, test_fhe_split_ascii_whitespace, test_fhe_split_char_pattern,
        test_fhe_split_string_pattern, test_splitn_char_pattern, test_splitn_string_pattern,
    };
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn test_next_chunk() {
        let encrypted_s = CLIENT_KEY.encrypt_str("b c d").unwrap();
        let (start_chunk, end_chunk) =
            SERVER_KEY.next_non_white_chunk(&encrypted_s, &SERVER_KEY.create_n(1));
        let clear_start = CLIENT_KEY.decrypt_integer(&start_chunk);
        let clear_end = CLIENT_KEY.decrypt_integer(&end_chunk);
        assert_eq!((clear_start, clear_end), (2, 3));
    }

    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, "", 1);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, " ", 2);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, " a", 3);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, "b ", 4);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, " a ", 5);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, "a a", 6);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, "a a ", 7);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, " a a", 8);
    test_fhe_split_ascii_whitespace!(split_ascii_whitespace, "\nr\ta", 9);
}
