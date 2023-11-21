use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn strip_encrypted_sufix(
        &self,
        s: &FheString,
        sufix: &FheString,
    ) -> (RadixCiphertext, FheString) {
        let reversed_result: (RadixCiphertext, FheString) = self.strip_encrypted_prefix(
            &self.reverse_string_content(&s),
            &self.reverse_string_content(&sufix),
        );
        (
            reversed_result.0,
            self.reverse_string_content(&reversed_result.1),
        )
    }

    pub fn strip_encrypted_prefix(
        &self,
        s: &FheString,
        prefix: &FheString,
    ) -> (RadixCiphertext, FheString) {
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
                self.strip_encrypted_prefix_no_init_padding(s, &self.remove_initial_padding(prefix))
            }
            (_, Padding::None | Padding::Final) => {
                self.strip_encrypted_prefix_no_init_padding(&self.remove_initial_padding(s), prefix)
            }
            _ => self.strip_encrypted_prefix_no_init_padding(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(prefix),
            ),
        }
    }

    pub fn strip_encrypted_prefix_no_init_padding(
        &self,
        s: &FheString,
        prefix: &FheString,
    ) -> (RadixCiphertext, FheString) {
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
    // fn test_strip_encrypted_prefix() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_padding("cdd", 2).unwrap();
    //     let encrypted_prefix = CLIENT_KEY.encrypt_str_padding("cd", 2).unwrap();

    //     let result = SERVER_KEY.strip_encrypted_prefix(&encrypted_str, &encrypted_prefix);

    //     let clear_starts_with = CLIENT_KEY.decrypt_u8(&result.0);
    //     let clear_striped = CLIENT_KEY.decrypt_string(&result.1).unwrap();

    //     assert_eq!(clear_starts_with, 1);
    //     assert_eq!(clear_striped, "d");
    // }

    #[test]
    fn test_strip_encrypted_sufix() {
        let encrypted_str = CLIENT_KEY.encrypt_str_padding("adi", 2).unwrap();
        let encrypted_sufix = CLIENT_KEY.encrypt_str_padding("di", 2).unwrap();

        let result = SERVER_KEY.strip_encrypted_sufix(&encrypted_str, &encrypted_sufix);

        let clear_starts_with = CLIENT_KEY.decrypt_u8(&result.0);
        let clear_striped = CLIENT_KEY.decrypt_string(&result.1).unwrap();

        assert_eq!(clear_starts_with, 1);
        assert_eq!(clear_striped, "a");
    }
}
