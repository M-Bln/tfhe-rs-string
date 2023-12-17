use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

impl StringServerKey {
    /// Return the `n`-th (encrypted) character of an encrypted string for `n` a clear index. Null
    /// characters are not counted. If `n` is out of range, returns a encryption of the null
    /// character.
    pub fn nth_clear(&self, s: &FheString, n: usize) -> FheAsciiChar {
        match s.padding {
            Padding::None | Padding::Final if n < s.content.len() => s.content[n].clone(),
            _ if n >= s.content.len() => FheAsciiChar(self.create_zero()),
            _ => self.nth_clear_padding_anywhere(s, n),
        }
    }

    /// Return the `n`-th (encrypted) character of an encrypted string for `n` an encrypted index.
    /// Null characters are not counted. If `n` is out of range, returns a encryption of the null
    /// character.
    pub fn nth_encrypted(&self, s: &FheString, n: &RadixCiphertext) -> FheAsciiChar {
        match s.padding {
            Padding::None | Padding::Final => self.nth_encrypted_final_padding(s, n),
            _ => self.nth_encrypted_padding_anywhere(s, n),
        }
    }

    /// Returns the `n`-th character of `s` for `n` a clear index and `s` an encrypted string
    /// enventually containing padding zeros anywhere. Returns an encrypted value of the null
    /// character if `n` is out of range.
    fn nth_clear_padding_anywhere(&self, s: &FheString, n: usize) -> FheAsciiChar {
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
            let current_char_non_null: BooleanBlock =
                self.integer_key.scalar_ne_parallelized(&c.0, 0);
            self.integer_key.add_assign_parallelized(
                &mut current_index,
                &self.bool_to_radix(&current_char_non_null),
            );
        }
        FheAsciiChar(result)
    }

    /// Returns the `n`-th character of `s` for `n` an encrypted index and `s` an encrypted string
    /// enventually containing padding zeros anywhere. Returns an encrypted value of the null
    /// character if `n` is out of range.
    fn nth_encrypted_padding_anywhere(
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
            let current_char_non_null: BooleanBlock =
                self.integer_key.scalar_ne_parallelized(&c.0, 0);
            self.integer_key.add_assign_parallelized(
                &mut current_index,
                &self.bool_to_radix(&current_char_non_null),
            );
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

    /// If `condition` is an encryption of `1` (for `true`), this function returns an `FheString`
    /// encrypting the same string as `if_string`. Otherwise it returns an encryption of the empty
    /// string.
    pub fn cmux_empty_string(&self, condition: &BooleanBlock, if_string: &FheString) -> FheString {
        let radix_condition = self.bool_to_radix(&condition);
        let mut content_result: Vec<FheAsciiChar> = Vec::with_capacity(if_string.content.len());
        let zero = self.create_zero();
        for c in if_string.content.iter() {
            content_result.push(FheAsciiChar(
                self.integer_key.cmux_parallelized(condition, &c.0, &zero),
            ));
        }
        let encrypted_length_result = match if_string.len() {
            FheStrLength::Clear(clear_length) => self
                .integer_key
                .scalar_mul_parallelized(&radix_condition, *clear_length as u32),
            FheStrLength::Encrypted(encrypted_length) => self
                .integer_key
                .mul_parallelized(&radix_condition, encrypted_length),
        };
        let padding_result = match if_string.padding {
            Padding::None => Padding::Final,
            if_string_padding => if_string_padding,
        };
        FheString {
            content: content_result,
            length: FheStrLength::Encrypted(encrypted_length_result),
            padding: padding_result,
        }
    }
}
