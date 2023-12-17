use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::split::ResultFheString;
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

impl StringServerKey {
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
        match &s.len() {
            ClearOrEncrypted::Clear(length) if end > *length => {
                return Err(ConversionError::OutOfRange)
            }
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                range_is_included = self
                    .integer_key
                    .scalar_ge_parallelized(encrypted_length, end as u64);
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
                self.substring_clear_final_padding(&self.push_padding_to_end(s), start, end),
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
            .boolean_bitand(&end_is_included, &start_before_end);

        match s.padding {
            Padding::None | Padding::Final => (
                range_is_included,
                self.substring_encrypted_final_padding(s, start, end),
            ),
            _ => (
                range_is_included,
                self.substring_encrypted_final_padding(&self.push_padding_to_end(s), start, end),
            ),
        }
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
            content,
            padding: s.padding,
            length,
        }
    }

    /// This function creates a copy of the substring of `s` between the `start`-th character
    /// (included) and the `end`-th character (excluded), for `start` and `end` encrypted indices
    /// and for `s` an encrypted string eventually with final padding zeros. If the range
    /// `start`-`end` is not included in `s` it returns the substring (eventually empty) at the
    /// intersection of the range and `s`. This function should only be called for `s.padding` being
    /// `Padding::None` or `Padding::Final`.
    pub fn substring_encrypted_final_padding(
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
        FheString {
            content: result_content,
            padding: result_padding,
            length: self.length_of_slice_encrypted_range(&s.length, start, end),
        }
    }

    /// This function creates a copy of the substring of `s` between the `start`-th character
    /// (included) and the end of the string, for `start` an encrypted inde and for `s` an encrypted
    /// string eventually with final padding zeros. If the  `start` is greater than or equal the
    /// length of `s`, it returns an (encrypted) empty string. This function should only be called
    /// for `s.padding` being `Padding::None` or `Padding::Final`.
    pub fn substring_from_encrypted_final_padding(
        &self,
        s: &FheString,
        start: &RadixCiphertext,
    ) -> FheString {
        let zero = &self.create_zero();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        for (n, c) in s.content.iter().enumerate() {
            // Check if the index `n` is in the range `start`-`end`.
            let in_range: BooleanBlock = self.integer_key.scalar_le_parallelized(start, n as u64);

            // If `n` is in range, take the content of `s` otherwise take a null character.
            let new_char_content: RadixCiphertext =
                self.integer_key.cmux_parallelized(&in_range, &c.0, &zero);
            result_content.push(FheAsciiChar(new_char_content));
        }

        let padding_result = match s.padding {
            Padding::None | Padding::Initial => Padding::Initial,
            Padding::Final => Padding::InitialAndFinal,
            _ => Padding::Anywhere,
        };

        FheString {
            content: result_content,
            padding: padding_result,
            length: self.length_of_slice_from_encrypted_range(&s.length, start),
        }
    }

    // The following functions compute the length of various substrings.

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
                self.length_of_slice_of_string_with_encrypted_length(len, start, end)
            }
        }
    }

    /// Returns the length of the intersection of a string of encrypted length
    /// `initial_encrypted_length` and of the range `start`-`end` for `start` and `end` clear
    /// indices.
    pub fn length_of_slice_of_string_with_encrypted_length(
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

    /// Returns the length of the intersection of a string of length `initial_length` and of the
    /// range `start`-.. for `start` an encrypted index.
    pub fn length_of_slice_from_encrypted_range(
        &self,
        length: &FheStrLength,
        start: &RadixCiphertext,
    ) -> FheStrLength {
        // The intersection of a string of length `length` and of the range `start`-`end` starts
        // either at `start` or at `length`.
        match length {
            ClearOrEncrypted::Encrypted(encrypted_length) => {
                ClearOrEncrypted::Encrypted(self.integer_key.sub_parallelized(
                    encrypted_length,
                    &self.integer_key.min_parallelized(start, encrypted_length),
                ))
            }
            ClearOrEncrypted::Clear(clear_length) => ClearOrEncrypted::Encrypted(
                self.integer_key.neg_parallelized(
                    &self.integer_key.scalar_sub_parallelized(
                        &self
                            .integer_key
                            .scalar_min_parallelized(start, *clear_length as u64),
                        *clear_length as u64,
                    ),
                ),
            ),
        }
    }
}
