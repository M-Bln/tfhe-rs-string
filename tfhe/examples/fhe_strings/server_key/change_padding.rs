use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    /// Returns the first element encrypting a non null character in content,
    /// replaces it in content by an encryption of the null character.
    /// If all character are null, return an encryption of the null character.
    pub fn pop_first_non_zero_char(&self, content_slice: &mut [FheAsciiChar]) -> FheAsciiChar {
        let mut previous_is_padding_zero = self.create_true();
        let mut result = self.create_zero();

        for c in content_slice {
            let current_is_zero = self.integer_key.scalar_eq_parallelized(&c.0, 0);

            let first_non_null = self.integer_key.boolean_bitand(
                &previous_is_padding_zero,
                &self.integer_key.boolean_bitnot(&current_is_zero),
            );

            // Encrypt same value as c if c is the first no null encrypted char,
            // encrypt zero otherwise
            let to_sub = self
                .integer_key
                .mul_parallelized(&c.0, &self.bool_to_radix(&first_non_null));

            // Compute the result
            self.integer_key
                .add_assign_parallelized(&mut result, &to_sub);

            // Update the value in content
            self.integer_key.sub_assign_parallelized(&mut c.0, &to_sub);

            // Update previous_is_padding_zero
            self.integer_key
                .boolean_bitand_assign(&mut previous_is_padding_zero, &current_is_zero);
        }
        FheAsciiChar(result)
    }

    /// Return the last element encrypting a non null character in content,
    /// replace it in content by an encryption of the null character.
    /// If all character are null, return an encryption of the null character.
    pub fn pop_last_non_zero_char(&self, content_slice: &mut [FheAsciiChar]) -> FheAsciiChar {
        let mut previous_is_padding_zero = self.create_true();
        let mut result = self.create_zero();

        for c in content_slice.iter_mut().rev() {
            let current_is_zero = self.integer_key.scalar_eq_parallelized(&c.0, 0);

            let first_non_null = self.integer_key.boolean_bitand(
                &previous_is_padding_zero,
                &self.integer_key.boolean_bitnot(&current_is_zero),
            );

            // Encrypt same value as c if c is the first no null encrypted char,
            // encrypt zero otherwise
            let to_sub = self
                .integer_key
                .mul_parallelized(&c.0, &self.bool_to_radix(&first_non_null));

            // Compute the result
            self.integer_key
                .add_assign_parallelized(&mut result, &to_sub);

            // Update the value in content
            self.integer_key.sub_assign_parallelized(&mut c.0, &to_sub);

            // Update previous_is_padding_zero
            self.integer_key
                .boolean_bitand_assign(&mut previous_is_padding_zero, &current_is_zero);
        }
        FheAsciiChar(result)
    }

    /// Replace the content of s with an encryption of the same string with all padding zeros pushed
    /// to the end.
    pub fn push_padding_to_end_assign(&self, s: &mut FheString) {
        match &s.padding {
            Padding::None | Padding::Final => return,
            _ => (),
        }
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut prev_content_slice = &mut s.content.clone()[..];
        for _ in 0..s.content.len() {
            result_content.push(self.pop_first_non_zero_char(prev_content_slice));
            prev_content_slice = &mut prev_content_slice[1..];
        }
        s.padding = Padding::Final;
        s.content = result_content;
    }

    /// Return an encryption of the same string, with the same content length, with all padding
    /// zeros pushed to the end.
    pub fn push_padding_to_end(&self, s: &FheString) -> FheString {
        match &s.padding {
            Padding::None | Padding::Final => return s.clone(),
            _ => (),
        }
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut prev_content_slice = &mut s.content.clone()[..];
        for _ in 0..s.content.len() {
            result_content.push(self.pop_first_non_zero_char(prev_content_slice));
            prev_content_slice = &mut prev_content_slice[1..];
        }
        FheString {
            content: result_content,
            padding: Padding::Final,
            length: s.length.clone(),
        }
    }

    /// Return an encryption of the same string, with the same content length,
    /// with all padding zeros pushed to the start of the string.
    pub fn push_padding_to_start(&self, s: &FheString) -> FheString {
        match &s.padding {
            Padding::None | Padding::Initial => return s.clone(),
            _ => (),
        }
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut prev_content_slice = &mut s.content.clone()[..];
        for i in 0..s.content.len() {
            result_content.push(self.pop_last_non_zero_char(prev_content_slice));
            prev_content_slice = &mut prev_content_slice[..(s.content.len() - i)];
        }
        FheString {
            content: result_content.into_iter().rev().collect(),
            padding: Padding::Final,
            length: s.length.clone(),
        }
    }
}
