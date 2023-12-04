use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    /// Check if s1 and s2 encrypt the same string, for s1 and s2 FheString.
    /// Return an encrypted value of 1 for true.
    pub fn eq(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        match (&s1.length, &s2.length) {
            (&FheStrLength::Clear(l1), &FheStrLength::Clear(l2)) if l1 != l2 => {
                return self.create_zero()
            }
            _ => (),
        }

        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.eq_no_init_padding(s1, s2)
            }
            (Padding::None | Padding::Final, _) => {
                self.eq_no_init_padding(s1, &self.remove_initial_padding(s2))
            }
            (_, Padding::None | Padding::Final) => {
                self.eq_no_init_padding(&self.remove_initial_padding(s1), s2)
            }
            _ => self.eq_no_init_padding(
                &self.remove_initial_padding(s1),
                &self.remove_initial_padding(s2),
            ),
        }
    }

    /// Check if s1 and s2 encrypt the same string up to case, for s1 and s2 FheString.
    /// Return an encrypted value of 1 for true.
    pub fn eq_ignore_case(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        match (&s1.length, &s2.length) {
            (&FheStrLength::Clear(l1), &FheStrLength::Clear(l2)) if l1 != l2 => {
                return self.create_zero()
            }
            _ => (),
        }

        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.eq_ignore_case_no_init_padding(s1, s2)
            }
            (Padding::None | Padding::Final, _) => {
                self.eq_ignore_case_no_init_padding(s1, &self.remove_initial_padding(s2))
            }
            (_, Padding::None | Padding::Final) => {
                self.eq_ignore_case_no_init_padding(&self.remove_initial_padding(s1), s2)
            }
            _ => self.eq_ignore_case_no_init_padding(
                &self.remove_initial_padding(s1),
                &self.remove_initial_padding(s2),
            ),
        }
    }

    /// Check if s1 encrypts a string which has the string encrypted by `prefix` as a prefix. Return
    /// an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn starts_with_encrypted(&self, s: &FheString, prefix: &FheString) -> RadixCiphertext {
        // If the prefix is longer than the encrypted string, return false
        match (&s.length, &prefix.length) {
            (&FheStrLength::Clear(l), &FheStrLength::Clear(l_prefix)) if l_prefix > l => {
                return self.create_zero()
            }
            (_, &FheStrLength::Clear(l_prefix)) if l_prefix > s.content.len() => {
                return self.create_zero()
            }
            _ => (),
        }

        match (s.padding, prefix.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.starts_with_encrypted_no_init_padding(s, prefix)
            }
            (Padding::None | Padding::Final, _) => {
                self.starts_with_encrypted_no_init_padding(s, &self.remove_initial_padding(prefix))
            }
            (_, Padding::None | Padding::Final) => {
                self.starts_with_encrypted_no_init_padding(&self.remove_initial_padding(s), prefix)
            }
            _ => self.starts_with_encrypted_no_init_padding(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(prefix),
            ),
        }
    }

    /// Check if s1 encrypts a string which has the string encrypted by `sufix` as a sufix. Return
    /// an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn ends_with_encrypted(&self, s: &FheString, sufix: &FheString) -> RadixCiphertext {
        self.starts_with_encrypted(
            &self.reverse_string_content(s),
            &self.reverse_string_content(sufix),
        )
    }

    /// Check if s1 encrypt the string s2, for s1 an FheString and s2 a clear &str.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn eq_clear(&self, s1: &FheString, s2: &str) -> RadixCiphertext {
        match s1.length {
            FheStrLength::Clear(l1) if l1 != s2.len() => return self.create_zero(),
            _ if s2.len() > s1.content.len() => return self.create_zero(),
            _ => (),
        }
        return match s1.padding {
            Padding::None | Padding::Final => self.eq_clear_no_init_padding(s1, s2),
            _ => self.eq_clear_no_init_padding(&self.remove_initial_padding(s1), s2),
        };
    }

    /// Check if the string encrypted by s1 is equal to the clear string s2 up to case. Return an
    /// encrypted value of 1 for true.
    pub fn eq_clear_ignore_case(&self, s1: &FheString, s2: &str) -> RadixCiphertext {
        match s1.length {
            FheStrLength::Clear(l1) if l1 != s2.len() => return self.create_zero(),
            _ if s2.len() > s1.content.len() => return self.create_zero(),
            _ => (),
        }
        return match s1.padding {
            Padding::None | Padding::Final => self.eq_clear_ignore_case_no_init_padding(s1, s2),
            _ => self.eq_clear_ignore_case_no_init_padding(&self.remove_initial_padding(s1), s2),
        };
    }

    /// Check if s1 encrypts a string which has the clear string `prefix` as a prefix. Return an
    /// encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn starts_with_clear(&self, s: &FheString, prefix: &str) -> RadixCiphertext {
        match s.length {
            FheStrLength::Clear(length) if prefix.len() > length => return self.create_zero(),
            _ if prefix.len() > s.content.len() => return self.create_zero(),
            _ => (),
        }
        return match s.padding {
            Padding::None | Padding::Final => self.starts_with_clear_no_init_padding(s, prefix),
            _ => self.starts_with_clear_no_init_padding(&self.remove_initial_padding(s), prefix),
        };
    }

    /// Check if `s1` encrypts a string which has the clear string `sufix` as a sufix. Return  an
    /// encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn ends_with_clear(&self, s: &FheString, sufix: &str) -> RadixCiphertext {
        self.starts_with_clear(
            &self.reverse_string_content(s),
            &sufix.chars().rev().collect::<String>(),
        )
    }

    /// Check if s1 and s2 encrypt the same string, for s1 and s2 FheString with no initial padding
    /// zeros. Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn eq_no_init_padding(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        // First the content are compared
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.content.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &self.compare_char(&s1.content[n], &s2.content[n], std::cmp::Ordering::Equal),
            )
        }

        // If content sizes mismatch, check if the extra characters are padding zeros
        if s1.content.len() > s2.content.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&s1.content[s2.content.len()].0, 0),
            );
        }
        if s2.content.len() > s1.content.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&s2.content[s1.content.len()].0, 0),
            );
        }
        result
    }

    /// Check if s1 and s2 encrypt the same string up to case, for s1 and s2 FheString with no
    /// initial padding zeros. Return an encrypted value of 1 for true and an encrypted value of
    /// 0 for false.
    pub fn eq_ignore_case_no_init_padding(
        &self,
        s1: &FheString,
        s2: &FheString,
    ) -> RadixCiphertext {
        // First the content are compared
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.content.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &self.eq_char_ignore_case(&s1.content[n], &s2.content[n]),
            )
        }

        // If content sizes mismatch, check if the extra characters are padding zeros
        if s1.content.len() > s2.content.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&s1.content[s2.content.len()].0, 0),
            );
        }
        if s2.content.len() > s1.content.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&s2.content[s1.content.len()].0, 0),
            );
        }
        result
    }

    /// Check if s encrypts a string which has the string encrypted by prefix as a prefix. The
    /// function assumes that both s and prefix do not have initial padding zeros. Return an
    /// encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn starts_with_encrypted_no_init_padding(
        &self,
        s: &FheString,
        prefix: &FheString,
    ) -> RadixCiphertext {
        // First the overlapping content are compared
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.content.len(), prefix.content.len()) {
            self.integer_key.unchecked_bitand_assign_parallelized(
                &mut result,
                &match prefix.padding {
                    // Padding is either None or Final
                    Padding::None => self.compare_char(
                        &s.content[n],
                        &prefix.content[n],
                        std::cmp::Ordering::Equal,
                    ),
                    _ => self.integer_key.unchecked_bitor_parallelized(
                        &self.compare_char(
                            &s.content[n],
                            &prefix.content[n],
                            std::cmp::Ordering::Equal,
                        ),
                        &self
                            .integer_key
                            .scalar_eq_parallelized(&prefix.content[n].0, 0),
                    ),
                },
            )
        }

        // If prefix content size is greater than s content size, check if the extra characters are
        // padding zeros
        if prefix.content.len() > s.content.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&prefix.content[s.content.len()].0, 0),
            );
        }
        result
    }

    /// Check if s1 encrypt the string s2, for s1 an FheString with no initial padding zeros and s2
    /// a clear &str. Return an encrypted value of 1 for true and an encrypted value of 0 for
    /// false.
    pub fn eq_clear_no_init_padding(&self, s1: &FheString, s2: &str) -> RadixCiphertext {
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &self.compare_clear_char(
                    &s1.content[n],
                    s2.as_bytes()[n],
                    std::cmp::Ordering::Equal,
                ),
            )
        }
        if s1.content.len() > s2.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&s1.content[s2.len()].0, 0),
            );
        }
        result
    }

    /// Check if s1 encrypt the string s2, for s1 an FheString with no initial padding zeros and s2
    /// a clear &str. Return an encrypted value of 1 for true and an encrypted value of 0 for
    /// false.
    pub fn eq_clear_ignore_case_no_init_padding(
        &self,
        s1: &FheString,
        s2: &str,
    ) -> RadixCiphertext {
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &self.eq_clear_char_ignore_case(&s1.content[n], s2.as_bytes()[n]),
            )
        }
        if s1.content.len() > s2.len() {
            return self.integer_key.bitand_parallelized(
                &result,
                &self
                    .integer_key
                    .scalar_eq_parallelized(&s1.content[s2.len()].0, 0),
            );
        }
        result
    }

    /// Check if s1 encrypts a string which has the clear string `prefix` as a prefix. The function
    /// assumes that both s and prefix do not have initial padding zeros. Return an encrypted value
    /// of 1 for true and an encrypted value of 0 for false.
    pub fn starts_with_clear_no_init_padding(
        &self,
        s: &FheString,
        prefix: &str,
    ) -> RadixCiphertext {
        // First the content are compared
        let mut result = self.create_true();
        for n in 0..std::cmp::min(s.content.len(), prefix.len()) {
            self.integer_key.bitand_assign_parallelized(
                &mut result,
                &self.compare_clear_char(
                    &s.content[n],
                    prefix.as_bytes()[n],
                    std::cmp::Ordering::Equal,
                ),
            )
        }
        result
    }

    /// Less or equal (<=).
    /// Check if the string encrypted by s1 is less than or equal to the string encrypted by s2.
    /// The order is the lexicographic order for bytes.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn le(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        self.compare(s1, s2, std::cmp::Ordering::Less)
    }

    /// Greater or equal (>=).
    /// Check if the string encrypted by s1 is greater or equal to the string encrypted by s2.
    /// The order is the lexicographic order for bytes.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn ge(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext {
        self.compare(s1, s2, std::cmp::Ordering::Greater)
    }

    /// Less or equal (<=) clear.
    /// Check if the string encrypted by s1 is less than or equal to the clear string s2.
    /// The order is the lexicographic order for bytes.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn le_clear(&self, s1: &FheString, s2: &str) -> RadixCiphertext {
        self.compare_clear(s1, s2, std::cmp::Ordering::Less)
    }

    /// Greater or equal (>=) clear.
    /// Check if the string encrypted by s1 is greater or equal to the clear string s2.
    /// The order is the lexicographic order for bytes.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    pub fn ge_clear(&self, s1: &FheString, s2: &str) -> RadixCiphertext {
        self.compare_clear(s1, s2, std::cmp::Ordering::Greater)
    }

    /// Compare the encrypted strings for the lexicographic order for bytes.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    /// If the operator is std::cmp::Ordering::Less,
    /// Return true if the string encrypted by s1 is less than or equal to the string encryptedd by
    /// s2. If the operator is std::cmp::Ordering::Greater,
    /// Return true if the string encrypted by s1 is less than or equal to the string encryptedd by
    /// s2. If the operator is std::cmp::Ordering::Equal,
    /// Return true if the string encrypted by s1 is equal to the string encryptedd by s2.
    /// For this case, using the function eq is more efficient.
    pub fn compare(
        &self,
        s1: &FheString,
        s2: &FheString,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        match (s1.padding, s2.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.compare_no_init_padding(s1, s2, operator)
            }
            (Padding::None | Padding::Final, _) => {
                self.compare_no_init_padding(s1, &self.remove_initial_padding(s2), operator)
            }
            (_, Padding::None | Padding::Final) => {
                self.compare_no_init_padding(&self.remove_initial_padding(s1), s2, operator)
            }
            _ => self.compare_no_init_padding(
                &self.remove_initial_padding(s1),
                &self.remove_initial_padding(s2),
                operator,
            ),
        }
    }

    /// Compare the encrypted string s1 with the clear string s2 for the lexicographic order for
    /// bytes. Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    /// If the operator is std::cmp::Ordering::Less,
    /// Return true if the string encrypted by s1 is less than or equal to the string s2.
    /// If the operator is std::cmp::Ordering::Greater,
    /// Return true if the string encrypted by s1 is less than or equal to the string s2.
    /// If the operator is std::cmp::Ordering::Equal,
    /// Return true if the string encrypted by s1 is equal to the string s2.
    /// For this case, using the function eq_clear is more efficient.
    pub fn compare_clear(
        &self,
        s1: &FheString,
        s2: &str,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        return match s1.padding {
            Padding::None | Padding::Final => self.compare_clear_no_init_padding(s1, s2, operator),
            _ => self.compare_clear_no_init_padding(&self.remove_initial_padding(s1), s2, operator),
        };
    }

    /// Implementation of compare, for FheString without initial padding zeros.
    pub fn compare_no_init_padding(
        &self,
        s1: &FheString,
        s2: &FheString,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        let mut result = self.create_zero();
        let mut equal_up_to_n_minus_1 = self.create_true();
        let mut equal_up_to_n = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.content.len()) {
            equal_up_to_n = self.integer_key.bitand_parallelized(
                &equal_up_to_n_minus_1,
                &self.compare_char(&s1.content[n], &s2.content[n], std::cmp::Ordering::Equal),
            );
            result = self.integer_key.cmux_parallelized(
                &self.integer_key.bitand_parallelized(
                    &equal_up_to_n_minus_1,
                    &self.integer_key.bitnot_parallelized(&equal_up_to_n),
                ),
                &self.compare_char(&s1.content[n], &s2.content[n], operator),
                &result,
            );
            equal_up_to_n_minus_1 = equal_up_to_n.clone();
        }
        if s1.content.len() > s2.content.len() {
            return match operator {
                std::cmp::Ordering::Greater => {
                    self.integer_key.bitor_parallelized(&result, &equal_up_to_n)
                }
                _ => self.integer_key.bitor_parallelized(
                    &result,
                    &self.integer_key.bitand_parallelized(
                        &equal_up_to_n,
                        &self
                            .integer_key
                            .scalar_eq_parallelized(&s1.content[s2.content.len()].0, 0),
                    ),
                ),
            };
        }
        if s2.content.len() > s1.content.len() {
            return match operator {
                std::cmp::Ordering::Less => {
                    self.integer_key.bitor_parallelized(&result, &equal_up_to_n)
                }
                _ => self.integer_key.bitor_parallelized(
                    &result,
                    &self.integer_key.bitand_parallelized(
                        &equal_up_to_n,
                        &self
                            .integer_key
                            .scalar_eq_parallelized(&s2.content[s1.content.len()].0, 0),
                    ),
                ),
            };
        }
        self.integer_key.bitor_parallelized(&result, &equal_up_to_n)
    }

    /// Implementation of compare_clear, for FheString without initial padding zeros.
    pub fn compare_clear_no_init_padding(
        &self,
        s1: &FheString,
        s2: &str,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        let mut result = self.create_zero();
        let mut equal_up_to_n_minus_1 = self.create_true();
        let mut equal_up_to_n = self.create_true();
        for n in 0..std::cmp::min(s1.content.len(), s2.len()) {
            equal_up_to_n = self.integer_key.bitand_parallelized(
                &equal_up_to_n_minus_1,
                &self.compare_clear_char(
                    &s1.content[n],
                    s2.as_bytes()[n],
                    std::cmp::Ordering::Equal,
                ),
            );
            result = self.integer_key.cmux_parallelized(
                &self.integer_key.bitand_parallelized(
                    &equal_up_to_n_minus_1,
                    &self.integer_key.bitnot_parallelized(&equal_up_to_n),
                ),
                &self.compare_clear_char(&s1.content[n], s2.as_bytes()[n], operator),
                &result,
            );
            equal_up_to_n_minus_1 = equal_up_to_n.clone();
        }
        if s1.content.len() > s2.len() {
            return match operator {
                std::cmp::Ordering::Greater => {
                    self.integer_key.bitor_parallelized(&result, &equal_up_to_n)
                }
                _ => self.integer_key.bitor_parallelized(
                    &result,
                    &self.integer_key.bitand_parallelized(
                        &equal_up_to_n,
                        &self
                            .integer_key
                            .scalar_eq_parallelized(&s1.content[s2.len()].0, 0),
                    ),
                ),
            };
        }
        if s2.len() > s1.content.len() {
            return match operator {
                std::cmp::Ordering::Less => {
                    self.integer_key.bitor_parallelized(&result, &equal_up_to_n)
                }
                _ => result,
            };
        }
        self.integer_key.bitor_parallelized(&result, &equal_up_to_n)
    }

    /// Compare the encrypted character c1 and the encrypted char c2 with the operator operator.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    /// If the operator is std::cmp::Ordering::Less,
    /// Return true if the character encrypted by c1 is less than or equal to the character
    /// encrypted by c2. If the operator is std::cmp::Ordering::Greater,
    /// Return true if the character encrypted by c1 is greater or equal to the character encrypted
    /// by c2. If the operator is std::cmp::Ordering::Equal,
    /// Return true if the character encrypted by c1 is equal to the character encrypted by c2.
    pub fn compare_char(
        &self,
        c1: &FheAsciiChar,
        c2: &FheAsciiChar,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        match operator {
            std::cmp::Ordering::Equal => self.integer_key.eq_parallelized(&c1.0, &c2.0),
            std::cmp::Ordering::Less => self.integer_key.le_parallelized(&c1.0, &c2.0),
            std::cmp::Ordering::Greater => self.integer_key.ge_parallelized(&c1.0, &c2.0),
        }
    }

    pub fn eq_char(&self, c1: &FheAsciiChar, c2: &FheAsciiChar) -> RadixCiphertext {
        self.integer_key.eq_parallelized(&c1.0, &c2.0)
    }

    pub fn eq_clear_char(&self, c1: &FheAsciiChar, c2: u8) -> RadixCiphertext {
        self.integer_key.scalar_eq_parallelized(&c1.0, c2)
    }

    /// Compare the encrypted character c1 and the clear char c2 with the operator `operator`.
    /// Return an encrypted value of 1 for true and an encrypted value of 0 for false.
    /// If the operator is std::cmp::Ordering::Less,
    /// Return true if the character encrypted by c1 is less than or equal to the clear character
    /// c2. If the operator is std::cmp::Ordering::Greater,
    /// Return true if the character encrypted by c1 is greater or equal to the clear character c2.
    /// If the operator is std::cmp::Ordering::Equal,
    /// Return true if the character encrypted by c1 is equal to the clear character c2.
    pub fn compare_clear_char(
        &self,
        c: &FheAsciiChar,
        scalar: u8,
        operator: std::cmp::Ordering,
    ) -> RadixCiphertext {
        match operator {
            std::cmp::Ordering::Equal => self.integer_key.scalar_eq_parallelized(&c.0, scalar),
            std::cmp::Ordering::Less => self.integer_key.scalar_le_parallelized(&c.0, scalar),
            std::cmp::Ordering::Greater => self.integer_key.scalar_ge_parallelized(&c.0, scalar),
        }
    }

    /// Compare the encrypted character c1 and the encryted char c2 ignoring case. Return an
    /// encrypted value of 1 if they are equal up to case and an encrypted value of 0 otherwise.
    pub fn eq_char_ignore_case(&self, c1: &FheAsciiChar, c2: &FheAsciiChar) -> RadixCiphertext {
        self.compare_char(
            &self.to_lowercase_char(&c1),
            &self.to_lowercase_char(&c2),
            std::cmp::Ordering::Equal,
        )
    }

    /// Compare the encrypted character c1 and the encryted char c2 ignoring case. Return an
    /// encrypted value of 1 if they are equal up to case and an encrypted value of 0 otherwise.
    pub fn eq_clear_char_ignore_case(&self, c: &FheAsciiChar, clear_char: u8) -> RadixCiphertext {
        let lowercase_clear_char: u8 = if clear_char > 64 && clear_char < 91 {
            clear_char + 32
        } else {
            clear_char
        };
        self.compare_clear_char(
            &self.to_lowercase_char(&c),
            lowercase_clear_char,
            std::cmp::Ordering::Equal,
        )
    }

    /// Return the first element encrypting a non null character in content,
    /// replace it in content by an encryption of the null character.
    /// If all character are null, return an encryption of the null character.
    pub fn pop_first_non_zero_char(&self, content_slice: &mut [FheAsciiChar]) -> FheAsciiChar {
        let mut previous_is_padding_zero = self.create_true();
        let mut result = self.create_zero();

        for c in content_slice {
            let current_is_zero = self.integer_key.scalar_eq_parallelized(&c.0, 0);

            let first_non_null = self.integer_key.bitand_parallelized(
                &previous_is_padding_zero,
                &self.integer_key.bitnot_parallelized(&current_is_zero),
            );

            // Encrypt same value as c if c is the first no null encrypted char,
            // encrypt zero otherwise
            let to_sub = self.integer_key.mul_parallelized(&c.0, &first_non_null);

            // Compute the result
            self.integer_key
                .add_assign_parallelized(&mut result, &to_sub);

            // Update the value in content
            self.integer_key.sub_assign_parallelized(&mut c.0, &to_sub);

            // Update previous_is_padding_zero
            self.integer_key
                .bitand_assign_parallelized(&mut previous_is_padding_zero, &current_is_zero);
        }
        FheAsciiChar(result)
    }

    /// Return the first element encrypting a non null character in content,
    /// replace it in content by an encryption of the null character.
    /// If all character are null, return an encryption of the null character.
    pub fn pop_last_non_zero_char(&self, content_slice: &mut [FheAsciiChar]) -> FheAsciiChar {
        let mut previous_is_padding_zero = self.create_true();
        let mut result = self.create_zero();

        for c in content_slice.iter_mut().rev() {
            let current_is_zero = self.integer_key.scalar_eq_parallelized(&c.0, 0);

            let first_non_null = self.integer_key.bitand_parallelized(
                &previous_is_padding_zero,
                &self.integer_key.bitnot_parallelized(&current_is_zero),
            );

            // Encrypt same value as c if c is the first no null encrypted char,
            // encrypt zero otherwise
            let to_sub = self.integer_key.mul_parallelized(&c.0, &first_non_null);

            // Compute the result
            self.integer_key
                .add_assign_parallelized(&mut result, &to_sub);

            // Update the value in content
            self.integer_key.sub_assign_parallelized(&mut c.0, &to_sub);

            // Update previous_is_padding_zero
            self.integer_key
                .bitand_assign_parallelized(&mut previous_is_padding_zero, &current_is_zero);
        }
        FheAsciiChar(result)
    }

    // /// Return the last element encrypting a non null character in content,
    // /// replace it in content by an encryption of the null character.
    // /// If all character are null, return an encryption of the null character.
    // pub fn pop_last_non_zero_char(&self, content_slice: &mut [FheAsciiChar]) -> FheAsciiChar {
    //     let mut previous_is_padding_zero = self.create_true();
    //     let mut result = self.create_zero();

    // 	for c in content_slice.iter().rev() {
    // 	    let current_non_zero = self.integer_key.scalar_ne_parallelized(&c.0, 0);
    // 	    let last_non_null = self.integer_key.bitand_parallelized(&current_non_zero,
    // &previous_is_padding_zero);

    //         // Encrypt same value as c if c is the first no null encrypted char,
    //         // encrypt zero otherwise
    //         let to_sub = self.integer_key.mul_parallelized(&c.0, &last_non_null);
    // 	    result = self.integer_key.cmux_parallelized(&last_non_null, &c.0, &result);

    // 	    // Encrypt same value as c if c is the first no null encrypted char,
    //         // encrypt zero otherwise
    //         let to_sub = self.integer_key.mul_parallelized(&c.0, &last_non_null);

    //         // Compute the result
    //         self.integer_key
    //             .add_assign_parallelized(&mut result, &to_sub);

    //         // Update the value in content
    //         self.integer_key.sub_assign_parallelized(&mut c.0, &to_sub);

    //         // Update previous_is_padding_zero
    //         self.integer_key
    //             .bitand_assign_parallelized(&mut previous_is_padding_zero, &current_is_zero);
    // 	}

    //     FheAsciiChar(result)
    // }

    /// Replace the content of s with an encryption of the same string with the same
    /// and without initial padding.
    pub fn remove_initial_padding_assign(&self, s: &mut FheString) {
        let mut result_content: Vec<FheAsciiChar> = Vec::with_capacity(s.content.len());
        let mut prev_content_slice = &mut s.content.clone()[..];
        for _ in 0..s.content.len() {
            result_content.push(self.pop_first_non_zero_char(prev_content_slice));
            prev_content_slice = &mut prev_content_slice[1..];
        }
        s.padding = Padding::Final;
        s.content = result_content;
    }

    /// Return an encryption of the same string, with the same content length,
    /// without initial padding.
    pub fn remove_initial_padding(&self, s: &FheString) -> FheString {
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
    /// without final padding.
    pub fn remove_final_padding(&self, s: &FheString) -> FheString {
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
    // fn test_pop_first_non_zero_char() {
    //     let mut encrypted_str = CLIENT_KEY
    //         .encrypt_ascii_vec(
    //             &vec![0, 97, 98, 0],
    //             Padding::InitialAndFinal,
    //             FheStrLength::Clear(2),
    //         )
    //         .unwrap();
    //     let poped_char = SERVER_KEY.pop_first_non_zero_char(&mut encrypted_str.content[..]);
    //     let decrypted_poped_char = CLIENT_KEY.decrypt_ascii_char(&poped_char);
    //     assert_eq!(decrypted_poped_char, 97);
    //     let decrypted_string = CLIENT_KEY.decrypt_string(&encrypted_str).unwrap();
    //     assert_eq!(decrypted_string, "b");
    // }

    #[test]
    fn test_pop_last_non_zero_char() {
        let mut encrypted_str = CLIENT_KEY
            .encrypt_ascii_vec(
                &vec![0, 97, 98, 0],
                Padding::InitialAndFinal,
                FheStrLength::Clear(2),
            )
            .unwrap();
        let poped_char = SERVER_KEY.pop_last_non_zero_char(&mut encrypted_str.content[..]);
        let decrypted_poped_char = CLIENT_KEY.decrypt_ascii_char(&poped_char);
        assert_eq!(decrypted_poped_char, 98);
        let decrypted_string = CLIENT_KEY.decrypt_string(&encrypted_str).unwrap();
        assert_eq!(decrypted_string, "a");
    }

    // #[test]
    // fn test_remove_initial_padding_assign() {
    //     let mut encrypted_str = CLIENT_KEY
    //         .encrypt_ascii_vec(
    //             &vec![0, 97],
    //             Padding::InitialAndFinal,
    //             FheStrLength::Clear(1),
    //         )
    //         .unwrap();
    //     SERVER_KEY.remove_initial_padding_assign(&mut encrypted_str);
    //     let decrypted_char = CLIENT_KEY.decrypt_ascii_char(&encrypted_str.content[0]);
    //     assert_eq!(decrypted_char, 97);
    //     assert_eq!(encrypted_str.padding, Padding::Final);

    //     let decrypted_string = CLIENT_KEY.decrypt_string(&encrypted_str).unwrap();
    //     assert_eq!(decrypted_string, "a");
    // }

    // #[test]
    // fn test_remove_initial_padding() {
    //     let encrypted_str = CLIENT_KEY
    //         .encrypt_ascii_vec(
    //             &vec![0, 97],
    //             Padding::InitialAndFinal,
    //             FheStrLength::Clear(1),
    //         )
    //         .unwrap();
    //     let encrypted_str_no_padding = SERVER_KEY.remove_initial_padding(&encrypted_str);
    //     let decrypted_char = CLIENT_KEY.decrypt_ascii_char(&encrypted_str_no_padding.content[0]);
    //     assert_eq!(decrypted_char, 97);
    //     assert_eq!(encrypted_str_no_padding.padding, Padding::Final);

    //     let decrypted_string = CLIENT_KEY
    //         .decrypt_string(&encrypted_str_no_padding)
    //         .unwrap();
    //     assert_eq!(decrypted_string, "a");
    // }

    // #[test]
    // fn test_le_ge() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str("cde").unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str("ce").unwrap();

    //     let le_str1_str2 = SERVER_KEY.le(&encrypted_str1, &encrypted_str2);
    //     let ge_str1_str2 = SERVER_KEY.ge(&encrypted_str1, &encrypted_str2);

    //     let clear_le_str1_str2 = CLIENT_KEY.decrypt_u8(&le_str1_str2);
    //     let clear_ge_str1_str2 = CLIENT_KEY.decrypt_u8(&ge_str1_str2);

    //     assert_eq!(clear_le_str1_str2, 1);
    //     assert_eq!(clear_ge_str1_str2, 0);
    // }

    // #[test]
    // fn test_eq() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("b", 1).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("bc", 1).unwrap();

    //     let eq_str1_str2 = SERVER_KEY.eq(&encrypted_str1, &encrypted_str2);
    //     let clear_eq_str1_str2 = CLIENT_KEY.decrypt_u8(&eq_str1_str2);

    //     assert_eq!(clear_eq_str1_str2, 0);
    // }

    // #[test]
    // fn test_neq() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("ba", 0).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("b", 1).unwrap();

    //     let eq_str1_str2 = SERVER_KEY.eq(&encrypted_str1, &encrypted_str2);
    //     let clear_eq_str1_str2 = CLIENT_KEY.decrypt_u8(&eq_str1_str2);

    //     assert_eq!(clear_eq_str1_str2, 0);
    // }

    // #[test]
    // fn test_le_ge_clear() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("bd", 1).unwrap();

    //     let le_str1_str2 = SERVER_KEY.le_clear(&encrypted_str1, "bd");
    //     let ge_str1_str2 = SERVER_KEY.ge_clear(&encrypted_str1, "ada");

    //     let clear_le_str1_str2 = CLIENT_KEY.decrypt_u8(&le_str1_str2);
    //     let clear_ge_str1_str2 = CLIENT_KEY.decrypt_u8(&ge_str1_str2);

    //     assert_eq!(clear_le_str1_str2, 1);
    //     assert_eq!(clear_ge_str1_str2, 1);
    // }

    // #[test]
    // fn test_eq_clear() {
    //     let encrypted_str1 = CLIENT_KEY
    //         .encrypt_ascii_vec(
    //             &vec![0, 0],
    //             Padding::InitialAndFinal,
    //             FheStrLength::Encrypted(SERVER_KEY.create_zero()),
    //         )
    //         .unwrap();

    //     let eq_str1_str2 = SERVER_KEY.eq_clear(&encrypted_str1, "");
    //     let eq_str1_str3 = SERVER_KEY.eq_clear(&encrypted_str1, "b");
    //     let eq_str1_str4 = SERVER_KEY.eq_clear(&encrypted_str1, "bd");

    //     let clear_eq_str1_str2 = CLIENT_KEY.decrypt_u8(&eq_str1_str2);
    //     let clear_eq_str1_str3 = CLIENT_KEY.decrypt_u8(&eq_str1_str3);
    //     let clear_eq_str1_str4 = CLIENT_KEY.decrypt_u8(&eq_str1_str4);

    //     assert_eq!(clear_eq_str1_str2, 1);
    //     assert_eq!(clear_eq_str1_str3, 0);
    //     assert_eq!(clear_eq_str1_str4, 0);
    // }

    // #[test]
    // fn test_starts_with_encrypted() {
    //     let encrypted_str = CLIENT_KEY
    //         .encrypt_ascii_vec(
    //             &vec![0, 98, 99],
    //             Padding::InitialAndFinal,
    //             FheStrLength::Clear(2),
    //         )
    //         .unwrap();
    //     let encrypted_prefix = CLIENT_KEY.encrypt_str("b").unwrap();

    //     let starts_with_result =
    //         SERVER_KEY.starts_with_encrypted(&encrypted_str, &encrypted_prefix);
    //     let clear_result = CLIENT_KEY.decrypt_u8(&starts_with_result);

    //     assert_eq!(clear_result, 1);
    // }

    // #[test]
    // fn test_starts_with_clear() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("bc", 2).unwrap();

    //     let mut starts_with_result = SERVER_KEY.starts_with_clear(&encrypted_str, "b");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&starts_with_result);
    //     assert_eq!(clear_result, 1);

    //     starts_with_result = SERVER_KEY.starts_with_clear(&encrypted_str, "");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&starts_with_result);
    //     assert_eq!(clear_result, 1);

    //     starts_with_result = SERVER_KEY.starts_with_clear(&encrypted_str, "bc");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&starts_with_result);
    //     assert_eq!(clear_result, 1);

    //     starts_with_result = SERVER_KEY.starts_with_clear(&encrypted_str, "def");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&starts_with_result);
    //     assert_eq!(clear_result, 0);

    //     starts_with_result = SERVER_KEY.starts_with_clear(&encrypted_str, "d");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&starts_with_result);
    //     assert_eq!(clear_result, 0);
    // }

    // #[test]
    // fn test_ends_with_encrypted() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("ccd", 2).unwrap();
    //     let encrypted_sufix = CLIENT_KEY.encrypt_str_random_padding("cd", 2).unwrap();

    //     let ends_with_result = SERVER_KEY.ends_with_encrypted(&encrypted_str, &encrypted_sufix);
    //     let starts_with_result = SERVER_KEY.starts_with_encrypted(&encrypted_str,
    // &encrypted_sufix);

    //     let clear_ends_with_result = CLIENT_KEY.decrypt_u8(&ends_with_result);
    //     let clear_starts_with_result = CLIENT_KEY.decrypt_u8(&starts_with_result);
    //     assert_eq!(clear_ends_with_result, 1);
    //     assert_eq!(clear_starts_with_result, 0);
    // }

    // #[test]
    // fn test_ends_with_clear() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("bc", 2).unwrap();

    //     let mut ends_with_result = SERVER_KEY.ends_with_clear(&encrypted_str, "c");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&ends_with_result);
    //     assert_eq!(clear_result, 1);

    //     ends_with_result = SERVER_KEY.ends_with_clear(&encrypted_str, "");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&ends_with_result);
    //     assert_eq!(clear_result, 1);

    //     ends_with_result = SERVER_KEY.ends_with_clear(&encrypted_str, "bc");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&ends_with_result);
    //     assert_eq!(clear_result, 1);

    //     ends_with_result = SERVER_KEY.ends_with_clear(&encrypted_str, "def");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&ends_with_result);
    //     assert_eq!(clear_result, 0);

    //     ends_with_result = SERVER_KEY.ends_with_clear(&encrypted_str, "b");
    //     let clear_result = CLIENT_KEY.decrypt_u8(&ends_with_result);
    //     assert_eq!(clear_result, 0);
    // }

    // #[test]
    // fn test_eq_ignore_case() {
    //     let encrypted_str1 = CLIENT_KEY.encrypt_str_random_padding("bB", 2).unwrap();
    //     let encrypted_str2 = CLIENT_KEY.encrypt_str_random_padding("bb", 2).unwrap();

    //     let eq_ignore_case_1_2 = SERVER_KEY.eq_ignore_case(&encrypted_str1, &encrypted_str2);

    //     let clear_eq_ignore_case_1_2 = CLIENT_KEY.decrypt_u8(&eq_ignore_case_1_2);
    //     assert_eq!(clear_eq_ignore_case_1_2, 1);
    // }

    // #[test]
    // fn test_eq_clear_ignore_case() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("bB", 2).unwrap();
    //     let result = SERVER_KEY.eq_clear_ignore_case(&encrypted_str, "BB");

    //     let clear_result = CLIENT_KEY.decrypt_u8(&result);
    //     assert_eq!(clear_result, 1);
    // }
}
