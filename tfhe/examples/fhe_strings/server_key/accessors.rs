use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

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

    pub fn final_substring_encrypted_final_padding(
        &self,
        s: &FheString,
        start: &RadixCiphertext,
    ) -> FheString {
        let zero = &self.create_zero();
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        for (n, c) in s.content.iter().enumerate() {
            // Check if the index `n` is in the range `start`-`end`.
            let in_range: RadixCiphertext =
                self.integer_key.scalar_le_parallelized(start, n as u64);

            // If `n` is in range, take the content of `s` otherwise take a null character.
            let new_char_content: RadixCiphertext =
                self.integer_key.cmux_parallelized(&in_range, &c.0, &zero);
            result_content.push(FheAsciiChar(new_char_content));
        }

        FheString {
            content: result_content,
            padding: s.padding,
            length: self.length_of_final_slice_encrypted_range(&s.length, start),
        }
    }

    pub fn length_of_final_slice_encrypted_range(
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
