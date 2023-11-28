use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

type ResultFheString = (RadixCiphertext, FheString);

pub struct FheSplit {
    pub parts: Vec<FheString>,
    pub number_parts: RadixCiphertext,
    pub current_index: usize,
}

impl StringServerKey {
    /// Return the `n`-th (encrypted) character of an encrypted string for `n` a clear index. Null
    /// characters are not counted. If `n` is out of range, returns a encryption of the null
    /// character.
    pub fn nth_clear(&self, s: &FheString, n: usize) -> FheAsciiChar {
        match s.padding {
            Padding::None | Padding::Final if n < s.content.len() => s.content[n].clone(),
            _ if n >= s.content.len() => FheAsciiChar(self.create_zero()),
            _ => self.nth_clear_with_padding(s, n),
        }
    }

    /// Return the `n`-th (encrypted) character of an encrypted string for `n` an encrypted index.
    /// Null characters are not counted. If `n` is out of range, returns a encryption of the null
    /// character.
    pub fn nth_encrypted(&self, s: &FheString, n: &RadixCiphertext) -> FheAsciiChar {
        match s.padding {
            Padding::None | Padding::Final => self.nth_encrypted_final_padding(s, n),
            _ => self.nth_encrypted_with_padding(s, n),
        }
    }

    /// This function create a copy of the substring of `s` between the `start`-th character
    /// (included) and the `end`-th character (excluded), for `start` and `end` clear indices. It
    /// returns a `Result` which is an error if an out of range error can be directly detected
    /// without decrypting the string, for instance if the range is larger than the content of `s`.
    /// Otherwise it returns a `ResultFheString` which indicates after decryption if an out of range
    /// error occured because of the padding.
    pub fn substring_clear(
        &self,
        s: &FheString,
        start: usize,
        end: usize,
    ) -> Result<ResultFheString, ConversionError> {
        // Check if the range is trivially not included in the string.
        if end < start || end > s.content.len() {
            return Err(ConversionError::OutOfRange);
        };

        let mut range_is_included = self.create_true();

        // Compare range to string length.
        match &s.length {
            ClearOrEncrypted::Clear(length) if end > *length => {
                return Err(ConversionError::OutOfRange)
            }
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                range_is_included = self
                    .integer_key
                    .scalar_ge_parallelized(&encrypted_length, end as u64);
            }
            _ => (),
        }

        match s.padding {
            Padding::None | Padding::Final => Ok((
                range_is_included,
                self.substring_clear_final_padding(s, start, end),
            )),
            _ => Ok((
                range_is_included,
                self.substring_clear_final_padding(&self.remove_initial_padding(s), start, end),
            )),
        }
    }

    /// This function creates a copy of the substring of `s` between the `start`-th character
    /// (included) and the `end`-th character (excluded), for `start` and `end` encrypted indices.
    /// It returns a `ResultFheString`, i.e. a `(RadixCiphertext, FheString)`. The first component
    /// is an encryption of a boolean `1` if the range is in the string `s` and `0` otherwise. The
    /// second component is the resulting substring, if the range `start`-`end` was not included in
    /// the string `s`, this component is still the intersection (eventually empty) of the range
    /// with `s`.
    pub fn substring_encrypted(
        &self,
        s: &FheString,
        start: &RadixCiphertext,
        end: &RadixCiphertext,
    ) -> ResultFheString {
        // Check if `end` is lower than or equal to the length of `s`
        let end_is_included = match &s.length {
            ClearOrEncrypted::Clear(length) => {
                self.integer_key.scalar_le_parallelized(end, *length as u64)
            }
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.le_parallelized(end, encrypted_length)
            }
        };
        let start_before_end = self.integer_key.le_parallelized(start, end);

        // The range is included if `start` <= `end` and `end` <= `s.len`
        let range_is_included = self
            .integer_key
            .bitand_parallelized(&end_is_included, &start_before_end);

        match s.padding {
            Padding::None | Padding::Final => (
                range_is_included,
                self.substring_encrypted_final_padding(s, start, end),
            ),
            _ => (
                range_is_included,
                self.substring_encrypted_final_padding(&self.remove_initial_padding(s), start, end),
            ),
        }
    }

    /// Returns the `n`-th character of `s` for `n` a clear index and `s` an encrypted string
    /// enventually containing padding zeros anywhere. Returns an encrypted value of the null
    /// character if `n` is out of range.
    fn nth_clear_with_padding(&self, s: &FheString, n: usize) -> FheAsciiChar {
        let mut current_index: RadixCiphertext = self.create_zero();
        let mut result = self.create_zero();
        for c in &s.content {
            // Check if the right index `n` is reached.
            let right_index = self
                .integer_key
                .scalar_eq_parallelized(&current_index, n as u64);

            // Update result when index `n` is reached.
            result = self
                .integer_key
                .cmux_parallelized(&right_index, &c.0, &result);

            // Increment `current_index` if the current char is non null
            let current_char_non_null: RadixCiphertext =
                self.integer_key.scalar_ne_parallelized(&c.0, 0);
            self.integer_key
                .add_assign_parallelized(&mut current_index, &current_char_non_null);
        }
        FheAsciiChar(result)
    }

    /// Returns the `n`-th character of `s` for `n` an encrypted index and `s` an encrypted string
    /// enventually containing padding zeros anywhere. Returns an encrypted value of the null
    /// character if `n` is out of range.
    fn nth_encrypted_with_padding(
        &self,
        s: &FheString,
        encrypted_n: &RadixCiphertext,
    ) -> FheAsciiChar {
        let mut current_index: RadixCiphertext = self.create_zero();
        let mut result = self.create_zero();
        for c in &s.content {
            // Check if the right index `n` is reached.
            let right_index = self
                .integer_key
                .eq_parallelized(&current_index, encrypted_n);

            // Update result when index `n` is reached.
            result = self
                .integer_key
                .cmux_parallelized(&right_index, &c.0, &result);

            // Increment `current_index` if the current char is non null
            let current_char_non_null: RadixCiphertext =
                self.integer_key.scalar_ne_parallelized(&c.0, 0);
            self.integer_key
                .add_assign_parallelized(&mut current_index, &current_char_non_null);
        }
        FheAsciiChar(result)
    }

    /// Returns the `n`-th character of `s` for `n` an encrypted index and `s` an encrypted string
    /// enventually with final padding zeros. Returns an encrypted value of the null character if
    /// `n` is out of range.
    fn nth_encrypted_final_padding(
        &self,
        s: &FheString,
        encrypted_n: &RadixCiphertext,
    ) -> FheAsciiChar {
        let mut result = self.create_zero();
        for (i, c) in s.content.iter().enumerate() {
            // Check if the right index `n` is reached.
            let right_index = self
                .integer_key
                .scalar_eq_parallelized(encrypted_n, i as u64);

            // Update result when index `n` is reached.
            result = self
                .integer_key
                .cmux_parallelized(&right_index, &c.0, &result)
        }
        FheAsciiChar(result)
    }

    /// This function creates a copy of the substring of `s` between the `start`-th character
    /// (included) and the `end`-th character (excluded), for `start` and `end` clear indices and
    /// for `s` an encrypted string eventually with final padding zeros. If the range `start`-`end`
    /// is not included in `s` it returns the substring (eventually empty) at the intersection of
    /// the range and `s`. This function should only be called for `s.padding` being `Padding::None`
    /// or `Padding::Final`.
    fn substring_clear_final_padding(&self, s: &FheString, start: usize, end: usize) -> FheString {
        let mut content: Vec<FheAsciiChar> = Vec::with_capacity(end - start);
        content.extend_from_slice(&s.content[start..end]);

        let length = self.length_of_slice(&s.length, start, end);
        FheString {
            content: content,
            padding: s.padding,
            length: length,
        }
    }

    /// This function creates a copy of the substring of `s` between the `start`-th character
    /// (included) and the `end`-th character (excluded), for `start` and `end` encrypted indices
    /// and for `s` an encrypted string eventually with final padding zeros. If the range
    /// `start`-`end` is not included in `s` it returns the substring (eventually empty) at the
    /// intersection of the range and `s`. This function should only be called for `s.padding` being
    /// `Padding::None` or `Padding::Final`.
    fn substring_encrypted_final_padding(
        &self,
        s: &FheString,
        start: &RadixCiphertext,
        end: &RadixCiphertext,
    ) -> FheString {
        let zero = &self.create_zero();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        for (n, c) in s.content.iter().enumerate() {
            // Check if the index `n` is in the range `start`-`end`.
            let in_range: RadixCiphertext = self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_le_parallelized(start, n as u64),
                &self.integer_key.scalar_gt_parallelized(end, n as u64),
            );

            // If `n` is in range, take the content of `s` otherwise take a null character.
            let new_char_content: RadixCiphertext =
                self.integer_key.cmux_parallelized(&in_range, &c.0, &zero);
            result_content.push(FheAsciiChar(new_char_content));
        }

        // // The intersection of `s` and the range `start`-`end` starts either at `start` or at
        // `s.length`. let new_start = match &s.length {
        //     ClearOrEncrypted::Encrypted(encrypted_length) => {
        //         self.integer_key.min_parallelized(start, encrypted_length)
        //     }
        //     ClearOrEncrypted::Clear(length) => self
        //         .integer_key
        //         .scalar_min_parallelized(start, *length as u64),
        // };

        // // The intersection of `s` and the range `start`-`end` ends either at `end` or at
        // `s.length`. let new_end = match &s.length {
        //     ClearOrEncrypted::Encrypted(encrypted_length) => {
        //         self.integer_key.min_parallelized(end, encrypted_length)
        //     }
        //     ClearOrEncrypted::Clear(length) => self
        //         .integer_key
        //         .scalar_min_parallelized(end, *length as u64),
        // };

        // // Compute the length of the resulting string, intersection of `s` and of the range
        // `start`-`end`. let length =
        //     ClearOrEncrypted::Encrypted(self.integer_key.scalar_max_parallelized(
        //         &self.integer_key.sub_parallelized(&new_end, &new_start),
        //         0,
        //     ));
        FheString {
            content: result_content,
            padding: s.padding,
            length: self.length_of_slice_encrypted_range(&s.length, start, end),
        }
    }

    /// Returns the length of the intersection of a string of length `initial_length` and of the
    /// range `start`-`end` for `start` and `end` clear indices.
    pub fn length_of_slice(
        &self,
        initial_length: &FheStrLength,
        start: usize,
        end: usize,
    ) -> FheStrLength {
        match &initial_length {
            ClearOrEncrypted::Clear(len) if start >= *len => ClearOrEncrypted::Clear(0),
            ClearOrEncrypted::Clear(len) => {
                ClearOrEncrypted::Clear(std::cmp::min(*len, end) - start)
            }
            ClearOrEncrypted::Encrypted(len) => {
                self.length_of_slice_from_encrypted_length(len, start, end)
            }
        }
    }

    /// Returns the length of the intersection of a string of encrypted length
    /// `initial_encrypted_length` and of the range `start`-`end` for `start` and `end` clear
    /// indices.
    pub fn length_of_slice_from_encrypted_length(
        &self,
        initial_encrypted_length: &RadixCiphertext,
        start: usize,
        end: usize,
    ) -> FheStrLength {
        let new_start = self
            .integer_key
            .scalar_min_parallelized(initial_encrypted_length, start as u64);
        let new_end = self
            .integer_key
            .scalar_min_parallelized(initial_encrypted_length, end as u64);
        ClearOrEncrypted::Encrypted(self.integer_key.sub_parallelized(&new_start, &new_end))
    }

    /// Returns the length of the intersection of a string of length `initial_length` and of the
    /// range `start`-`end` for `start` and `end` encrypted indices.
    pub fn length_of_slice_encrypted_range(
        &self,
        length: &FheStrLength,
        start: &RadixCiphertext,
        end: &RadixCiphertext,
    ) -> FheStrLength {
        // The intersection of a string of length `length` and of the range `start`-`end` starts
        // either at `start` or at `length`.
        let new_start = match length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.min_parallelized(start, encrypted_length)
            }
            ClearOrEncrypted::Clear(length) => self
                .integer_key
                .scalar_min_parallelized(start, *length as u64),
        };

        // The intersection of a string of length `length` and of the range `start`-`end` ends
        // either at `end` or at `length`.
        let new_end = match length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                self.integer_key.min_parallelized(end, encrypted_length)
            }
            ClearOrEncrypted::Clear(length) => self
                .integer_key
                .scalar_min_parallelized(end, *length as u64),
        };

        ClearOrEncrypted::Encrypted(
            self.integer_key.scalar_max_parallelized(
                &self.integer_key.sub_parallelized(&new_end, &new_start),
                0,
            ),
        )
    }
    
    pub fn split_encrypted_final_padding(&self, s: &FheString, pattern: &FheString) -> FheSplit {
	// Compute the maximum number of parts of the result.
        let maximum_number_of_parts = match &s.length {
            ClearOrEncrypted::Clear(length) => *length + 1,
            _ => s.content.len() +1,
        };
        let mut parts: Vec<FheString> = Vec::with_capacity(maximum_number_of_parts);

	// `current_from` holds the index of the start of the remaining of the string still needing processing. It is first initialized to the first index of the first occurence of the pattern if any, to the length of s otherwise.
        let mut current_from = self.connected_find_unpadded_string(s, pattern).1;

	// The first part before the first occurence of the pattern is pushed to `parts`
        parts.push(
            self.substring_encrypted(s, &self.create_zero(), &current_from)
                .1,
        );
	
	// `current_from` is then incremented by the length of the pattern and now points to the remaining of the string after the first pattern. 
        match &pattern.length {
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .add_assign_parallelized(&mut current_from, encrypted_length),
            ClearOrEncrypted::Clear(clear_length) => self
                .integer_key
                .scalar_add_assign_parallelized(&mut current_from, *clear_length as u64),
        }
        for _ in 1..maximum_number_of_parts {
            let current_next = self.find_from(s, pattern, &current_from);
            parts.push(
                self.substring_encrypted(s, &current_from, &current_next.1)
                    .1,
            );
            current_from = current_next.1;
        }
        FheSplit {
	    parts: parts,
	    number_parts: self.create_zero(),
	    current_index: 0,
	}
    }

    pub fn find_from(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);

            // let increment_index = self.integer_key.bitand_parallelized(
            //     &self.integer_key.scalar_eq_parallelized(&found, 0),
            //     &self.integer_key.scalar_ge_parallelized(&s.content[n].0, 1),
            // );
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }
    pub fn increment_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        match s.padding {
            Padding::None | Padding::Final => self.integer_key.scalar_eq_parallelized(&found, 0),
            _ => self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_eq_parallelized(&found, 0),
                &self
                    .integer_key
                    .scalar_ne_parallelized(&s.content[content_index].0, 0),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
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
    //     //        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);

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
    //     //        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);
    //     let result = SERVER_KEY.substring_clear(&encrypted_str, 1, 3).unwrap();

    //     let encrypted_substr = result.1;
    //     let encrypted_flag = result.0;

    //     assert_eq!(CLIENT_KEY.decrypt_string(&encrypted_substr).unwrap(), "d");
    //     assert_eq!(CLIENT_KEY.decrypt_u8(&encrypted_flag), 0);
    // }

    // #[test]
    // fn test_substring_encrypted() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("adc", 0).unwrap();
    //     //        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);
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
    // fn test_find_from() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("aac").unwrap();
    //     //        let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("ac", 2).unwrap();
    //     //      let encrypted_str3 = SERVER_KEY.reverse_string_content(&encrypted_str2);

    //     let encrypted_pattern = CLIENT_KEY.encrypt_str("a").unwrap();

    //     let result =
    //         SERVER_KEY.find_from(&encrypted_str, &encrypted_pattern, &SERVER_KEY.create_n(1));
    //     //let result2 = SERVER_KEY.find_string(&encrypted_str3, &encrypted_pattern);

    //     let clear_result = (
    //         CLIENT_KEY.decrypt_u8(&result.0),
    //         CLIENT_KEY.decrypt_u8(&result.1),
    //     );

    //     // let clear_result2 = (
    //     //     CLIENT_KEY.decrypt_u8(&result2.0),
    //     //     CLIENT_KEY.decrypt_u8(&result2.1),
    //     // );

    //     assert_eq!(clear_result, (1, 1));
    //     //   assert_eq!(clear_result2, (1, 0));
    // }

    #[test]
    fn test_split_encrypted() {
        let encrypted_str0 = CLIENT_KEY.encrypt_str("ba").unwrap();
        let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);
        //        let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("ac", 2).unwrap();
        //      let encrypted_str3 = SERVER_KEY.reverse_string_content(&encrypted_str2);

        let encrypted_pattern = CLIENT_KEY.encrypt_str("a").unwrap();

        let result = SERVER_KEY.split_encrypted_final_padding(&encrypted_str, &encrypted_pattern);
        //let result2 = SERVER_KEY.find_string(&encrypted_str3, &encrypted_pattern);

        let clear_result = (
            CLIENT_KEY.decrypt_string(&result.parts[0]).unwrap(),
            CLIENT_KEY.decrypt_string(&result.parts[1]).unwrap(),
        );

        // let clear_result2 = (
        //     CLIENT_KEY.decrypt_u8(&result2.0),
        //     CLIENT_KEY.decrypt_u8(&result2.1),
        // );

        assert_eq!(clear_result, (String::from(""), String::from("b")));
        //   assert_eq!(clear_result2, (1, 0));
    }
}
