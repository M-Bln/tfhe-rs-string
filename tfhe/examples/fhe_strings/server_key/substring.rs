use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::server_key::split::ResultFheString;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

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
            let in_range: RadixCiphertext = self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_le_parallelized(start, n as u64),
                &self.integer_key.scalar_gt_parallelized(end, n as u64),
            );

            // If `n` is in range, take the content of `s` otherwise take a null character.
            let new_char_content: RadixCiphertext =
                self.integer_key.cmux_parallelized(&in_range, &c.0, &zero);
            result_content.push(FheAsciiChar(new_char_content));
        }

        FheString {
            content: result_content,
            padding: s.padding,
            length: self.length_of_slice_encrypted_range(&s.length, start, end),
        }
    }
}
