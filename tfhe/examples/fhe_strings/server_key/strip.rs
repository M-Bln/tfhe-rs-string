use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub type FheOptionString = (RadixCiphertext, FheString);

impl StringServerKey {
    pub fn strip_prefix(&self, s: &FheString, prefix: &impl FhePattern) -> FheOptionString {
        prefix.strip_prefix_in(self, s)
    }

    pub fn strip_suffix(&self, s: &FheString, suffix: &impl FhePattern) -> FheOptionString {
        suffix.strip_suffix_in(self, s)
    }

    pub fn strip_encrypted_suffix(&self, s: &FheString, suffix: &FheString) -> FheOptionString {
        let reversed_result: FheOptionString = self.strip_encrypted_prefix(
            &self.reverse_string_content(&s),
            &self.reverse_string_content(&suffix),
        );
        (
            reversed_result.0,
            self.reverse_string_content(&reversed_result.1),
        )
    }

    pub fn strip_char_prefix(
        &self,
        s: &FheString,
        prefix: &impl FheCharPattern,
    ) -> FheOptionString {
        match s.len() {
            FheStrLength::Clear(0) => {
                return (
                    self.create_zero(),
                    FheString {
                        content: vec![],
                        length: FheStrLength::Clear(0),
                        padding: Padding::None,
                    },
                )
            }
            _ if s.content.is_empty() => {
                return (
                    self.create_zero(),
                    FheString {
                        content: vec![],
                        length: FheStrLength::Clear(0),
                        padding: Padding::None,
                    },
                )
            }
            _ => (),
        }
        match s.padding {
            Padding::None | Padding::Final => self.strip_char_prefix_no_init_padding(s, prefix),
            _ => self.strip_char_prefix_no_init_padding(&self.push_padding_to_end(s), prefix),
            //  _ => self.strip_char_prefix_any_padding(s, prefix), TODO
        }
    }

    pub fn strip_char_prefix_no_init_padding(
        &self,
        s: &FheString,
        prefix: &impl FheCharPattern,
    ) -> FheOptionString {
        let is_prefix = prefix.fhe_eq(self, &s.content[0]);
        let radix_first_char =
            self.integer_key
                .cmux_parallelized(&is_prefix, &self.create_zero(), &s.content[0].0);
        let mut result_content = vec![FheAsciiChar(radix_first_char)];
        result_content.extend_from_slice(&s.content[1..]);
        let result_length = self.sub_radix_to_length(s.len(), &is_prefix);
        let result_padding = match s.padding {
            Padding::None => Padding::Initial,
            Padding::Final => Padding::InitialAndFinal,
            s_padding => s_padding,
        };
        (
            is_prefix,
            FheString {
                content: result_content,
                length: result_length,
                padding: result_padding,
            },
        )
    }

    pub fn strip_encrypted_prefix(&self, s: &FheString, prefix: &FheString) -> FheOptionString {
        let zero = self.create_zero();
        match (&s.length, &prefix.length) {
            (&FheStrLength::Clear(l), &FheStrLength::Clear(l_prefix)) if l_prefix > l => {
                return (zero, s.clone())
            }
            (_, &FheStrLength::Clear(l_prefix)) if l_prefix > s.content.len() => {
                return (zero, s.clone())
            }
            _ => (),
        }
        match (s.padding, prefix.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.strip_encrypted_prefix_no_init_padding(s, prefix)
            }
            (Padding::None | Padding::Final, _) => {
                self.strip_encrypted_prefix_no_init_padding(s, &self.push_padding_to_end(prefix))
            }
            (_, Padding::None | Padding::Final) => {
                self.strip_encrypted_prefix_no_init_padding(&self.push_padding_to_end(s), prefix)
            }
            _ => self.strip_encrypted_prefix_no_init_padding(
                &self.push_padding_to_end(s),
                &self.push_padding_to_end(prefix),
            ),
        }
    }

    pub fn strip_clear_prefix(&self, s: &FheString, prefix: &str) -> FheOptionString {
        match s.len() {
            FheStrLength::Clear(clear_length) if *clear_length < prefix.len() => {
                return (self.create_zero(), s.clone())
            }
            _ if s.content.len() < prefix.len() => return (self.create_zero(), s.clone()),
            _ => (),
        }
        match s.padding {
            Padding::None | Padding::Final => self.strip_clear_prefix_no_init_padding(s, prefix),
            _ => self.strip_clear_prefix_no_init_padding(&self.push_padding_to_end(s), prefix),
        }
    }

    pub fn strip_clear_prefix_no_init_padding(
        &self,
        s: &FheString,
        prefix: &str,
    ) -> FheOptionString {
        if s.content.len() < prefix.len() {
            return (self.create_zero(), s.clone());
        }

        let zero = self.create_zero();
        let is_prefix = prefix.is_prefix_of_string(self, s);
        let mut result_content: Vec<FheAsciiChar> = vec![];

        for (i, c) in prefix.bytes().enumerate() {
            result_content.push(FheAsciiChar(self.integer_key.cmux_parallelized(
                &is_prefix,
                &zero,
                &s.content[i].0,
            )))
        }

        result_content.extend_from_slice(&s.content[prefix.len()..]);
        let result_length = match s.len() {
            FheStrLength::Clear(clear_length) => {
                FheStrLength::Encrypted(self.integer_key.cmux_parallelized(
                    &is_prefix,
                    &self.create_n((clear_length - prefix.len()) as u8),
                    &self.create_n(*clear_length as u8),
                ))
            }
            FheStrLength::Encrypted(encrypted_length) => FheStrLength::Encrypted(
                self.integer_key.cmux_parallelized(
                    &is_prefix,
                    &self
                        .integer_key
                        .scalar_sub_parallelized(encrypted_length, prefix.len() as u32),
                    encrypted_length,
                ),
            ),
        };
        let result_padding = match s.padding {
            Padding::None => Padding::Initial,
            Padding::Final => Padding::InitialAndFinal,
            s_padding => s_padding,
        };
        (
            is_prefix,
            FheString {
                content: result_content,
                padding: result_padding,
                length: result_length,
            },
        )
    }

    pub fn strip_encrypted_prefix_no_init_padding(
        &self,
        s: &FheString,
        prefix: &FheString,
    ) -> FheOptionString {
        let starts_with_prefix = self.starts_with_encrypted_no_init_padding(s, prefix);
        let content = match &prefix.length {
            ClearOrEncrypted::Clear(prefix_length) => self
                .strip_clear_length_encrypted_prefix_content(
                    &s.content,
                    &starts_with_prefix,
                    *prefix_length as u8,
                ),
            ClearOrEncrypted::Encrypted(prefix_length) => self
                .strip_encrypted_length_encrypted_prefix_content(
                    &s.content,
                    &prefix.content,
                    &starts_with_prefix,
                    &prefix_length.clone(),
                ),
        };
        let length = self.new_length(&s.length, &prefix.length, &starts_with_prefix);
        (
            starts_with_prefix,
            FheString {
                content: content,
                length: length,
                padding: match s.padding {
                    Padding::None => Padding::Initial,
                    _ => Padding::InitialAndFinal,
                },
            },
        )
    }

    fn new_length(
        &self,
        string_length: &FheStrLength,
        prefix_length: &FheStrLength,
        starts_with_prefix: &RadixCiphertext,
    ) -> FheStrLength {
        match (string_length, prefix_length) {
            (ClearOrEncrypted::Clear(str_length), ClearOrEncrypted::Clear(pfx_length)) => {
                ClearOrEncrypted::Encrypted(self.integer_key.unchecked_cmux(
                    &starts_with_prefix,
                    &self.create_n(*str_length as u8 - *pfx_length as u8),
                    &self.create_n(*str_length as u8),
                ))
            }
            (ClearOrEncrypted::Encrypted(str_length), ClearOrEncrypted::Clear(pfx_length)) => {
                ClearOrEncrypted::Encrypted(
                    self.integer_key.unchecked_cmux(
                        &starts_with_prefix,
                        &self
                            .integer_key
                            .scalar_sub_parallelized(str_length, *pfx_length as u8),
                        &str_length,
                    ),
                )
            }
            (ClearOrEncrypted::Clear(str_length), ClearOrEncrypted::Encrypted(pfx_length)) => {
                ClearOrEncrypted::Encrypted(self.integer_key.unchecked_cmux(
                    &starts_with_prefix,
                    &self.integer_key.scalar_add_parallelized(
                        &self.integer_key.neg_parallelized(pfx_length),
                        *str_length as u8,
                    ),
                    &self.create_n(*str_length as u8),
                ))
            }
            (ClearOrEncrypted::Encrypted(str_length), ClearOrEncrypted::Encrypted(pfx_length)) => {
                ClearOrEncrypted::Encrypted(self.integer_key.unchecked_cmux(
                    &starts_with_prefix,
                    &self.integer_key.sub_parallelized(str_length, pfx_length),
                    &str_length,
                ))
            }
        }
    }

    fn strip_clear_length_encrypted_prefix_content(
        &self,
        content: &[FheAsciiChar],
        starts_with_prefix: &RadixCiphertext,
        prefix_length: u8,
    ) -> Vec<FheAsciiChar> {
        let mut result: Vec<FheAsciiChar> = Vec::with_capacity(content.len());
        let zero = self.create_zero();
        for n in 0..prefix_length {
            result.push(FheAsciiChar(self.integer_key.unchecked_cmux(
                starts_with_prefix,
                &zero,
                &content[n as usize].0,
            )));
        }
        result.extend_from_slice(&content[(prefix_length as usize)..]);
        result
    }

    fn strip_encrypted_length_encrypted_prefix_content(
        &self,
        content: &[FheAsciiChar],
        prefix_content: &[FheAsciiChar],
        starts_with_prefix: &RadixCiphertext,
        prefix_length: &RadixCiphertext,
    ) -> Vec<FheAsciiChar> {
        let mut result: Vec<FheAsciiChar> = Vec::with_capacity(content.len());
        let overlapping_content_length = std::cmp::min(content.len(), prefix_content.len());
        let zero = self.create_zero();
        for n in 0..overlapping_content_length {
            let erase = self.integer_key.bitand_parallelized(
                starts_with_prefix,
                &self
                    .integer_key
                    .scalar_ge_parallelized(prefix_length, (n + 1) as u8),
            );
            result.push(FheAsciiChar(self.integer_key.unchecked_cmux(
                &erase,
                &zero,
                &content[n].0,
            )));
        }
        result.extend_from_slice(&content[overlapping_content_length..]);
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys_test, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{
        compare_result, test_fhe_add_char_pattern, test_fhe_string_string_pattern,
        test_option_string_char_pattern, test_option_string_string_pattern,
        test_replace_clear_n_string_pattern,
    };
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    // test_option_string_string_pattern!(strip_prefix,"","");
    // test_option_string_string_pattern!(strip_prefix,"","a");
    // test_option_string_string_pattern!(strip_prefix,"a","");
    // test_option_string_string_pattern!(strip_prefix,"a","a");
    // test_option_string_string_pattern!(strip_prefix,"a","b");
    // test_option_string_string_pattern!(strip_prefix,"ab","a");
    // test_option_string_string_pattern!(strip_prefix,"ab","b");
    // test_option_string_string_pattern!(strip_prefix,"ab","ab");
    // test_option_string_string_pattern!(strip_prefix,"abc","ab");
    // test_option_string_string_pattern!(strip_prefix,"abc","bc");

    // test_option_string_char_pattern!(strip_prefix,"",'a');
    // test_option_string_char_pattern!(strip_prefix,"a",'a');
    // test_option_string_char_pattern!(strip_prefix,"b",'a');
    // test_option_string_char_pattern!(strip_prefix,"ab",'a');
    // test_option_string_char_pattern!(strip_prefix,"ba",'a');

    test_option_string_string_pattern!(strip_suffix, "", "");
    test_option_string_string_pattern!(strip_suffix, "", "a");
    test_option_string_string_pattern!(strip_suffix, "a", "");
    test_option_string_string_pattern!(strip_suffix, "a", "a");
    test_option_string_string_pattern!(strip_suffix, "a", "b");
    test_option_string_string_pattern!(strip_suffix, "ab", "a");
    test_option_string_string_pattern!(strip_suffix, "ab", "b");
    test_option_string_string_pattern!(strip_suffix, "ab", "ab");
    test_option_string_string_pattern!(strip_suffix, "abc", "ab");
    test_option_string_string_pattern!(strip_suffix, "abc", "bc");

    test_option_string_char_pattern!(strip_suffix, "", 'a');
    test_option_string_char_pattern!(strip_suffix, "a", 'a');
    test_option_string_char_pattern!(strip_suffix, "b", 'a');
    test_option_string_char_pattern!(strip_suffix, "ab", 'a');
    test_option_string_char_pattern!(strip_suffix, "ba", 'a');

    // #[test]
    // fn test_strip_encrypted_prefix() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("cdd", 2).unwrap();
    //     let encrypted_prefix = CLIENT_KEY.encrypt_str_random_padding("cd", 2).unwrap();

    //     let result = SERVER_KEY.strip_encrypted_prefix(&encrypted_str, &encrypted_prefix);

    //     let clear_starts_with = CLIENT_KEY.decrypt_u8(&result.0);
    //     let clear_striped = CLIENT_KEY.decrypt_string(&result.1).unwrap();

    //     assert_eq!(clear_starts_with, 1);
    //     assert_eq!(clear_striped, "d");
    // }

    // #[test]
    // fn test_strip_encrypted_suffix() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("adi", 2).unwrap();
    //     let encrypted_suffix = CLIENT_KEY.encrypt_str_random_padding("di", 2).unwrap();

    //     let result = SERVER_KEY.strip_encrypted_suffix(&encrypted_str, &encrypted_suffix);

    //     let clear_starts_with = CLIENT_KEY.decrypt_u8(&result.0);
    //     let clear_striped = CLIENT_KEY.decrypt_string(&result.1).unwrap();

    //     assert_eq!(clear_starts_with, 1);
    //     assert_eq!(clear_striped, "a");
    // }
}
