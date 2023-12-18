use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::integer_arg::FheIntegerArg;
use crate::pattern::FhePattern;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;

impl StringServerKey {
    /// Replaces each occurence of old_pattern in s by new. Works for string and character, clear or
    /// encrypted patterns. It return value can have padding zeros anywhere. # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aba").unwrap();
    /// let old_pattern = client_key.encrypt_str("a").unwrap();
    /// let new_pattern = client_key.encrypt_str("cc").unwrap();
    /// let result = server_key.replace(&encrypted_str, &old_pattern, &new_pattern);
    /// let clear_result = client_key.decrypt_string(&result).unwrap();
    /// assert_eq!(clear_result, "ccbcc");
    /// ```
    pub fn replace(
        &self,
        s: &FheString,
        old_pattern: &impl FhePattern,
        new: &impl FhePattern,
    ) -> FheString {
        new.insert_in(self, &self.split(s, old_pattern))
    }

    /// Replaces the n first occurences of old_pattern in s by new. Works for string and character,
    /// clear or encrypted patterns. Works for clear or encrypted n. It return value can have
    /// padding zeros anywhere. # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aba").unwrap();
    /// let old_pattern = client_key.encrypt_str("a").unwrap();
    /// let new_pattern = client_key.encrypt_str("cc").unwrap();
    /// let n = client_key.encrypt_integer(1);
    /// let result = server_key.replacen(&encrypted_str, &old_pattern, &new_pattern, &n);
    /// let clear_result = client_key.decrypt_string(&result).unwrap();
    /// assert_eq!(clear_result, "ccba");
    /// ```
    pub fn replacen(
        &self,
        s: &FheString,
        old_pattern: &impl FhePattern,
        new: &impl FhePattern,
        n: &impl FheIntegerArg,
    ) -> FheString {
        new.insert_in(self, &self.splitn(s, &n.add_one(self), old_pattern))
    }

    /// Insert the encrypted string new between each parts of the vector of parts of fhe_split.
    pub fn insert_in_fhe_split_result_padded_anywhere(
        &self,
        fhe_split: &FheSplit,
        new: &FheString,
    ) -> FheString {
        let mut result = FheString {
            content: Vec::new(),
            length: ClearOrEncrypted::Clear(0),
            padding: Padding::None,
        };
        for (i, part) in fhe_split.parts.iter().enumerate() {
            let part_if_in_range = self.cmux_empty_string(
                &self
                    .integer_key
                    .scalar_gt_parallelized(&fhe_split.number_parts, i as u32),
                part,
            );
            result = self.add(result, &part_if_in_range);
            let new_if_in_range = self.cmux_empty_string(
                &self
                    .integer_key
                    .scalar_gt_parallelized(&fhe_split.number_parts, (i + 1) as u32),
                new,
            );
            result = self.add(result, &new_if_in_range);
        }
        result
    }

    /// Insert the encrypted char new between each parts of the vector of parts of fhe_split.
    pub fn insert_char_in_fhe_split_result_padded_anywhere(
        &self,
        fhe_split: &FheSplit,
        new: &FheAsciiChar,
    ) -> FheString {
        let mut result = FheString {
            content: Vec::new(),
            length: ClearOrEncrypted::Clear(0),
            padding: Padding::None,
        };
        let zero = self.create_zero();
        for (i, part) in fhe_split.parts.iter().enumerate() {
            let part_if_in_range = self.cmux_empty_string(
                &self
                    .integer_key
                    .scalar_gt_parallelized(&fhe_split.number_parts, i as u32),
                part,
            );
            result = self.add(result, &part_if_in_range);
            let in_range = self
                .integer_key
                .scalar_gt_parallelized(&fhe_split.number_parts, (i + 1) as u32);
            let new_if_in_range =
                FheAsciiChar(self.integer_key.cmux_parallelized(&in_range, &new.0, &zero));
            result = self.add(result, &new_if_in_range);
        }
        result
    }

    // pub fn old_replace(
    //     &self,
    //     s: &FheString,
    //     old_pattern: &impl FhePattern,
    //     new: &FheString,
    // ) -> FheString {
    //     let splited_s = self.split(s, old_pattern);
    //     let mut result = FheString {
    //         content: Vec::new(),
    //         length: ClearOrEncrypted::Clear(0),
    //         padding: Padding::None,
    //     };
    //     let number_replacement = self.integer_key.cmux_parallelized(
    //         &self
    //             .integer_key
    //             .scalar_ne_parallelized(&splited_s.number_parts, 0),
    //         &self
    //             .integer_key
    //             .scalar_sub_parallelized(&splited_s.number_parts, 1),
    //         &self.create_zero(),
    //     );
    //     let mut total_length = FheStrLength::Clear(0);
    //     for part in splited_s.parts.iter() {
    //         result = self.add(result, part);
    //         result = self.add(result, new);
    //         total_length = self.add_length(&total_length, part.len());
    //     }

    //     total_length = self.add_length(
    //         &total_length,
    //         &self.mult_length_by_radix(new.len(), &number_replacement),
    //     );
    //     match result.padding {
    //         Padding::None | Padding::Final => self.erase_after(result, total_length),
    //         _ => self.erase_after(self.push_padding_to_end(&result), total_length),
    //     }
    // }

    // assume s has final padding at worst
    // pub fn erase_after(&self, mut s: FheString, result_length: FheStrLength) -> FheString {
    //     let zero = self.create_zero();
    //     s.length = result_length;
    //     match &s.length {
    //         FheStrLength::Encrypted(encrypted_length) => {
    //             for i in 0..s.content.len() {
    //                 s.content[i] = FheAsciiChar(
    //                     self.integer_key.cmux_parallelized(
    //                         &self
    //                             .integer_key
    //                             .scalar_le_parallelized(encrypted_length, i as u32),
    //                         &zero,
    //                         &s.content[i].0,
    //                     ),
    //                 );
    //             }
    //         }
    //         FheStrLength::Clear(clear_length) => {
    //             s.content.truncate(*clear_length);
    //             s.padding = Padding::None;
    //         }
    //     }
    //     s
    // }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys_test, FheStrLength};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_fhe_string_string_pattern};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    //test_fhe_string_string_pattern!(replace, "", "b", "e");
    //test_fhe_string_string_pattern!(replace, "", "", "e");
    //test_fhe_string_string_pattern!(replace, "", "", "");
    //test_fhe_string_string_pattern!(replace, "ab", "", "e");
    test_fhe_string_string_pattern!(replace, "abc", "b", "e");
    test_fhe_string_string_pattern!(replace, "ab", "b", "c");
    test_fhe_string_string_pattern!(replace, "bbb", "b", "c");
    // test_replace_clear_n_string_pattern!(replacen, "aaa", "a", "b", 0);
    // test_replace_clear_n_string_pattern!(replacen, "aaa", "a", "b", 1);
    // test_replace_clear_n_string_pattern!(replacen, "abc", "b", "e", 0);
    // test_replace_clear_n_string_pattern!(replacen, "abc", "b", "e", 1);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ab", "ba", 0);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ab", "ba", 1);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ab", "ba", 2);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ab", "ba", 3);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ab", "ba", 4);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ba", "du", 0);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ba", "du", 1);
}
