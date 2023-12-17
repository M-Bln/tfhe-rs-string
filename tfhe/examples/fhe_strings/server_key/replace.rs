use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::integer_arg::FheIntegerArg;
use crate::pattern::FhePattern;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    // pub fn insert_in_fhe_split(&self, fhe_split: &FheSplit, new: &FheString) -> FheString {
    //     let mut result = FheString {
    //         content: Vec::new(),
    //         length: ClearOrEncrypted::Clear(0),
    //         padding: Padding::None,
    //     };
    //     let number_replacement = self.integer_key.cmux_parallelized(
    //         &self
    //             .integer_key
    //             .scalar_ne_parallelized(&fhe_split.number_parts, 0),
    //         &self
    //             .integer_key
    //             .scalar_sub_parallelized(&fhe_split.number_parts, 1),
    //         &self.create_zero(),
    //     );
    //     let mut total_length = FheStrLength::Clear(0);
    //     for part in fhe_split.parts.iter() {
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
    //         _ => self.erase_after(self.remove_initial_padding(&result), total_length),
    //     }
    // }

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

    // pub fn replace(&self, s: &FheString, old_pattern: &impl FhePattern, new: &FheString) ->
    // FheString { 	self.insert_in_fhe_split(&self.split(s, old_pattern), new)
    // }

    pub fn replacen(
        &self,
        s: &FheString,
        old_pattern: &impl FhePattern,
        new: &impl FhePattern,
        n: &impl FheIntegerArg,
    ) -> FheString {
        new.insert_in(&self, &self.splitn(s, &n.add_one(self), old_pattern))
    }

    pub fn replace(
        &self,
        s: &FheString,
        old_pattern: &impl FhePattern,
        new: &impl FhePattern,
    ) -> FheString {
        new.insert_in(&self, &self.split(s, old_pattern))
    }

    // pub fn replacen(&self, s: &FheString, old_pattern: &impl FhePattern, new: &FheString, n:
    // &impl FheIntegerArg) -> FheString { 	self.insert_in_fhe_split_result_padded_anywhere(&
    // self.splitn(&n.add_one(self), s, old_pattern), new) }

    pub fn old_replace(
        &self,
        s: &FheString,
        old_pattern: &impl FhePattern,
        new: &FheString,
    ) -> FheString {
        let splited_s = self.split(s, old_pattern);
        let mut result = FheString {
            content: Vec::new(),
            length: ClearOrEncrypted::Clear(0),
            padding: Padding::None,
        };
        let number_replacement = self.integer_key.cmux_parallelized(
            &self
                .integer_key
                .scalar_ne_parallelized(&splited_s.number_parts, 0),
            &self
                .integer_key
                .scalar_sub_parallelized(&splited_s.number_parts, 1),
            &self.create_zero(),
        );
        let mut total_length = FheStrLength::Clear(0);
        for part in splited_s.parts.iter() {
            result = self.add(result, part);
            result = self.add(result, new);
            total_length = self.add_length(&total_length, part.len());
        }

        total_length = self.add_length(
            &total_length,
            &self.mult_length_by_radix(new.len(), &number_replacement),
        );
        match result.padding {
            Padding::None | Padding::Final => self.erase_after(result, total_length),
            _ => self.erase_after(self.push_padding_to_end(&result), total_length),
        }
    }

    // assume s has final padding at worst
    pub fn erase_after(&self, mut s: FheString, result_length: FheStrLength) -> FheString {
        let zero = self.create_zero();
        s.length = result_length;
        match &s.length {
            FheStrLength::Encrypted(encrypted_length) => {
                for i in 0..s.content.len() {
                    s.content[i] = FheAsciiChar(
                        self.integer_key.cmux_parallelized(
                            &self
                                .integer_key
                                .scalar_le_parallelized(encrypted_length, i as u32),
                            &zero,
                            &s.content[i].0,
                        ),
                    );
                }
            }
            FheStrLength::Clear(clear_length) => {
                s.content.truncate(*clear_length);
                s.padding = Padding::None;
            }
        }
        return s;
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys_test, FheAsciiChar, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{
        compare_result, test_fhe_add_char_pattern, test_fhe_string_string_pattern,
        test_replace_clear_n_string_pattern,
    };
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    test_fhe_string_string_pattern!(replace, "", "b", "e");
    test_fhe_string_string_pattern!(replace, "", "", "e");
    test_fhe_string_string_pattern!(replace, "", "", "");
    test_fhe_string_string_pattern!(replace, "ab", "", "e");
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
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ba", "du", 2);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ba", "du", 3);
    // test_replace_clear_n_string_pattern!(replacen, "abababa", "ba", "du", 4);
    // test_replace_clear_n_string_pattern!(replacen, "ab", "c", "d", 2);
    // test_replace_clear_n_string_pattern!(replacen, "ab", "c", "d", 0);
    //test_replace_clear_n_string_pattern!(replacen,  "aaa", "a", "b", 4);

    // test_fhe_string_string_pattern!(replace_result_padded_anywhere, "ab", "b", "c");
    // test_fhe_string_string_pattern!(replace, "a", "", "");
    // #[test]
    // fn test_split_padding() {
    // 	let encrypted_s = CLIENT_KEY.encrypt_str("abc").unwrap();
    // 	let splited = SERVER_KEY.split(&encrypted_s, &"b");
    // 	let padding_vec : Vec<Padding> = splited.parts.iter().map(|s| s.padding).collect();
    // 	assert_eq!(padding_vec, vec![Padding::InitialAndFinal, Padding::InitialAndFinal,
    // Padding::InitialAndFinal, Padding::InitialAndFinal, Padding::InitialAndFinal]); }
    // test_fhe_string_string_pattern!(replace, "a", "", "e");
    //    test_fhe_string_string_pattern!(replace, "ab", "b", "u");
    // test_fhe_string_string_pattern!(add, "ab", "");
    // test_fhe_string_string_pattern!(add, "aezfb", "cdfzefzef");
    // test_fhe_string_string_pattern!(add, "", "cd");

    // test_fhe_string_char_pattern!(add, "", 'a');
    // test_fhe_string_char_pattern!(add, "ab", 'a');
    // test_fhe_string_char_pattern!(add, "aezfb", 'a');
}
