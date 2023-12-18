use crate::ciphertext::{ClearOrEncrypted, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::{BooleanBlock, RadixCiphertext};

/// FHE version of Option<int>, an encryption of (true, n) corresponds to Som(n), an encryption of
/// (false, _) corresponds to None
pub type FheOptionInt = (BooleanBlock, RadixCiphertext);

impl StringServerKey {
    /// Searches for pattern in haystack. Returns an FheOptionInt Some(n) if pattern is find and
    /// first starts at index n, None otherwise.
    /// # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aba").unwrap();
    /// let pattern = client_key.encrypt_str("a").unwrap();
    /// let result = server_key.find(&encrypted_str, &pattern);
    /// let clear_result_bool = client_key.decrypt_integer(&server_key.bool_to_radix(&result.0));
    /// assert_eq!(clear_result_bool, 1);
    /// let clear_result_index = client_key.decrypt_integer(&result.1);
    /// assert_eq!(clear_result_index, 0);
    /// ```
    pub fn find(&self, haystack: &FheString, pattern: &impl FhePattern) -> FheOptionInt {
        pattern.find_in(self, haystack)
    }

    /// Searches, from the end, for pattern in haystack. Returns an FheOptionInt Some(n) if pattern
    /// is find and first starts at index n, None otherwise.
    /// # Examples
    ///
    /// ```
    /// let (client_key, server_key) = gen_keys_test();
    /// let encrypted_str = client_key.encrypt_str("aba").unwrap();
    /// let pattern = client_key.encrypt_str("a").unwrap();
    /// let result = server_key.rfind(&encrypted_str, &pattern);
    /// let clear_result_bool = client_key.decrypt_integer(&server_key.bool_to_radix(&result.0));
    /// assert_eq!(clear_result_bool, 1);
    /// let clear_result_index = client_key.decrypt_integer(&result.1);
    /// assert_eq!(clear_result_index, 2);
    /// ```
    pub fn rfind(&self, haystack: &FheString, pattern: &impl FhePattern) -> FheOptionInt {
        pattern.rfind_in(self, haystack)
    }

    /// Searches for pattern in haystack. Returns an FheOptionInt Some(n) if pattern is find and
    /// first starts at index n, None otherwise. The pattern being a character clear or encrypted.
    /// Works even if s has padding anywhere.
    pub fn find_char(&self, s: &FheString, char_pattern: &impl FheCharPattern) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        if let FheStrLength::Clear(0) = s.length {
            return (fhe_false, zero);
        }
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match: BooleanBlock = char_pattern.fhe_eq(self, &s.content[n]);
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            // As s might has padding anywhere, the index is incremented if and only if the pattern
            // is not found yet and the current character is not a padding zero.
            // TODO: another version of the function when we know that the string has at worst final
            // padding.
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Same as find_char but from the end
    pub fn rfind_char(&self, s: &FheString, char_pattern: &impl FheCharPattern) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        if let FheStrLength::Clear(0) = s.length {
            return (fhe_false, zero);
        }
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) =
            (fhe_false.clone(), self.initial_index_rfind_char(&s.length));
        for n in (0..s.content.len()).rev() {
            let current_match: BooleanBlock = char_pattern.fhe_eq(self, &s.content[n]);
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Searches for pattern (an encrypted string) in haystack. Returns an FheOptionInt Some(n) if
    /// pattern is find and first starts at index n, None otherwise.
    /// The complexity depends on the padding. It is O(pattern.content.len() * s.content.len()) is
    /// both string have final padding at worst. Add a O(pattern.content.len()^2) if the patterns
    /// has padding worst than final. Add a O(haystack.content.len()^2) if haystack has padding
    /// anywhere.
    pub fn find_string(&self, s: &FheString, pattern: &FheString) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }

        // Dispatch according to padding.
        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::None | Padding::Final) => {
                self.connected_find_unpadded_string(&self.push_padding_to_end(s), pattern)
            }
            (Padding::Anywhere, _) => self.connected_find_unpadded_string(
                &self.push_padding_to_end(s),
                &self.push_padding_to_end(pattern),
            ),
            (_, Padding::None | Padding::Final) => self.connected_find_unpadded_string(s, pattern),
            _ => self.connected_find_unpadded_string(s, &self.push_padding_to_end(pattern)),
        }
    }

    /// Searches for pattern (a clear string) in haystack. Returns an FheOptionInt Some(n) if
    /// pattern is find and first starts at index n, None otherwise.
    /// The complexity depends on the padding. It is O(pattern.content.len() * s.content.len()) is
    /// both string have final padding at worst. Add a O(haystack.content.len()^2) if haystack has
    /// padding anywhere.
    pub fn find_clear_string(&self, s: &FheString, pattern: &str) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), zero),
            (content_length, pattern_length) if pattern_length > content_length => {
                return (fhe_false, zero)
            }
            _ => (),
        }

        match s.padding {
            Padding::Anywhere => {
                self.connected_find_clear_string(&self.push_padding_to_end(s), pattern)
            }
            _ => self.connected_find_clear_string(s, pattern),
        }
    }

    /// Searches from the end for pattern (a clear string) in s. Returns an FheOptionInt Some(n) if
    /// pattern is find and first starts at index n, None otherwise.
    pub fn rfind_clear_string(&self, s: &FheString, pattern: &str) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), zero),
            (content_length, pattern_length) if pattern_length > content_length => {
                return (fhe_false, zero)
            }
            _ => (),
        }

        match s.padding {
            Padding::Anywhere => {
                self.connected_rfind_clear_string(&self.push_padding_to_end(s), pattern)
            }
            _ => self.connected_rfind_clear_string(s, pattern),
        }
    }

    /// Searches for pattern (an encrypted string) in s. Returns an FheOptionInt Some(n) if pattern
    /// is find and first starts at index n, None otherwise. It assumes that s is connected (its
    /// padding is at wors Initial and Final) and that the pattern has at worst final padding.
    pub fn connected_find_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Search for pattern (a clear string) in s. Returns an FheOptionInt Some(n) if pattern is find
    /// and first starts at index n, None otherwise. It assumes that s is connected (its padding is
    /// at worst Initial and Final).
    pub fn connected_find_clear_string(&self, s: &FheString, pattern: &str) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            //            let current_match = self.starts_with_encrypted_vec(&s.content[n..],
            // pattern);
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// same as connected_find_clear_string but from the end.
    pub fn connected_rfind_clear_string(&self, s: &FheString, pattern: &str) -> FheOptionInt {
        let mut index = self.initial_index_rfind(&s.length);
        if pattern.is_empty() {
            return (self.create_true(), index);
        }
        let mut found = self.create_false();
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            //let current_match = self.starts_with_vec_clear(&s.content[n..],  pattern);
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);

            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Searches for pattern (an encrypted string) in s starting at (encrypted) index from. Assuming
    /// that both pattern and s have at worst final padding and that pattern is not the empty
    /// string. The complexity is O(pattern.content.len() * s.content.len()).
    pub fn find_from_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.boolean_bitand(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Searches for pattern (a clear string) in s starting at (encrypted) index from. Assuming that
    /// s has at worst final padding.
    pub fn find_clear_from_final_padding(
        &self,
        s: &FheString,
        pattern: &str,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), from.clone()),
            (0, _) => return (fhe_false, zero),
            _ => (),
        }
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.boolean_bitand(
                &pattern.is_prefix_of_slice(self, &s.content[n..]),
                //                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Searches for pattern (a clear or encrypted character) in s starting at (encrypted) index
    /// from. Assuming that s has at worst final padding.
    pub fn find_char_from_final_padding(
        &self,
        s: &FheString,
        pattern: &impl FheCharPattern,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        if s.content.is_empty() {
            return (fhe_false, zero);
        }
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.boolean_bitand(
                &pattern.is_prefix_of_slice(self, &s.content[n..]),
                //                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Same as find_from_final_padding but also works when pattern encrypts the empty string
    /// (eventually with padding).
    pub fn find_from_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut found, mut index): (BooleanBlock, RadixCiphertext) = (fhe_false, zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.boolean_bitand(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &self.min_length_radix(&s.length, from),
            &index,
        );
        (found, index)
    }

    /// Same as find_string but from the end.
    pub fn rfind_string(&self, s: &FheString, pattern: &FheString) -> FheOptionInt {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            // (0,_) => return (self.eq_clear_char(&pattern.content[0]),
            // self.initial_index_rfind(&s.length)),
            _ => (),
        }

        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::None | Padding::Final) => {
                self.connected_rfind_unpadded_string(&self.push_padding_to_end(s), pattern)
            }
            (Padding::Anywhere, _) => self.connected_rfind_unpadded_string(
                &self.push_padding_to_end(s),
                &self.push_padding_to_end(pattern),
            ),
            (_, Padding::None | Padding::Final) => self.connected_rfind_unpadded_string(s, pattern),
            _ => self.connected_rfind_unpadded_string(s, &self.push_padding_to_end(pattern)),
        }
    }

    /// Same as connected_find_unpadded_string but from the end.
    pub fn connected_rfind_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> FheOptionInt {
        let fhe_false: BooleanBlock = self.create_false();
        let initial_index = self.initial_index_rfind(&s.length);
        let mut index = initial_index.clone();
        let mut found = fhe_false;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &initial_index,
            &index,
        );
        (found, index)
    }

    /// Searches, from the end, for pattern (an encrypted string) in s. The search starts at
    /// (encrypted) index from. Meaning that for a non empty pattern, the maximum index at which it
    /// can be found is 'from -1'. Assuming that both pattern and s have at worst final padding and
    /// that pattern is not the empty string.
    pub fn rfind_from_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
        to: &RadixCiphertext,
    ) -> FheOptionInt {
        let fhe_false: BooleanBlock = self.create_false();
        let mut index = self.initial_index_rfind(&s.length);
        let mut found = fhe_false;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.increment_index(s, n, &found);
            let current_match = self.integer_key.boolean_bitand(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(to, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Same as rfind_from_final_padding but also works if the pattern is empty. The empty pattern
    /// is found at index 'from-1'.
    pub fn rfind_from_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (from_greater_than_zero, zero),
            (0, _) => {
                return (
                    self.integer_key.boolean_bitand(
                        &self.eq_clear_char(&pattern.content[0], 0),
                        &from_greater_than_zero,
                    ),
                    zero,
                )
            }
            _ => (),
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = fhe_false;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.boolean_bitand(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &self.min_length_radix(
                &s.length,
                &self.integer_key.scalar_sub_parallelized(from, 1),
            ),
            &index,
        );
        (found, index)
    }

    /// Same as rfind_from_final_padding but for clear string pattern.
    pub fn rfind_clear_from_final_padding(
        &self,
        s: &FheString,
        pattern: &str,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        //        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        if s.content.len() < pattern.len() {
            return (fhe_false, zero);
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = fhe_false;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.boolean_bitand(
                &pattern.is_prefix_of_slice(self, &s.content[n..]),
                //                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Same as rfind_from_final_padding but for character pattern.
    pub fn rfind_char_from_final_padding(
        &self,
        s: &FheString,
        pattern: &impl FheCharPattern,
        from: &RadixCiphertext,
    ) -> FheOptionInt {
        //        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        let fhe_false: BooleanBlock = self.create_false();
        if s.content.is_empty() {
            return (fhe_false, zero);
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = fhe_false;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.boolean_bitand(
                &pattern.fhe_eq(self, &s.content[n]),
                //                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .boolean_bitor_assign(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    /// Return a radix encoding the min of length and to.
    pub fn min_length_radix(&self, length: &FheStrLength, to: &RadixCiphertext) -> RadixCiphertext {
        match length {
            FheStrLength::Clear(clear_length) => self
                .integer_key
                .scalar_min_parallelized(to, *clear_length as u64),
            FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(to, l),
        }
    }

    pub fn initial_index_rfind_allow_empty_pattern(
        &self,
        length: &FheStrLength,
    ) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length - 1) as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_sub_parallelized(encrypted_length, 1),
        }
    }

    pub fn initial_index_rfind(&self, length: &FheStrLength) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n(*clear_length as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => encrypted_length.clone(),
        }
    }

    pub fn initial_index_rfind_char(&self, length: &FheStrLength) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(0) => self.create_zero(),
            ClearOrEncrypted::Clear(clear_length) => self.create_n(*clear_length as u8 - 1),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_sub_parallelized(encrypted_length, 1),
        }
    }

    pub fn length_to_radix_plus_one(&self, length: &FheStrLength) -> RadixCiphertext {
        match length {
            ClearOrEncrypted::Clear(clear_length) => self.create_n((*clear_length + 1) as u8),
            ClearOrEncrypted::Encrypted(encrypted_length) => self
                .integer_key
                .scalar_add_parallelized(encrypted_length, 1),
        }
    }

    // The index is incremented if and only if the pattern is not found yet and the current
    // character is not a padding zero.
    pub fn increment_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &BooleanBlock,
    ) -> RadixCiphertext {
        match s.padding {
            Padding::None | Padding::Final => self.bool_to_radix(
                &self
                    .integer_key
                    .scalar_eq_parallelized(&self.bool_to_radix(found), 0),
            ),
            _ => self.bool_to_radix(
                &self.integer_key.boolean_bitand(
                    &self.integer_key.boolean_bitnot(found),
                    &self
                        .integer_key
                        .scalar_ne_parallelized(&s.content[content_index].0, 0),
                ),
            ),
        }
    }

    pub fn rincrement_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &BooleanBlock,
    ) -> RadixCiphertext {
        self.bool_to_radix(
            &self.integer_key.boolean_bitand(
                &self.integer_key.boolean_bitnot(found),
                &self
                    .integer_key
                    .scalar_ne_parallelized(&s.content[content_index].0, 0),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys_test;
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_option_index_char_pattern, test_option_index_string_pattern};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    test_option_index_char_pattern!(find, "abc", 'a');
    test_option_index_char_pattern!(find, "abc", 'b');
    test_option_index_char_pattern!(find, "abc", 'c');
    test_option_index_char_pattern!(find, "abc", 'd');
    //test_option_index_char_pattern!(find, "", 'b');

    // test_char_fhe_option!(find, "abc", 'a');
    // test_char_fhe_option!(find, "abc", 'b');
    // test_char_fhe_option!(find, "abc", 'c');
    // test_char_fhe_option!(find, "abc", 'd');
    // test_char_fhe_option!(find, "", 'b');

    test_option_index_string_pattern!(find, "abc", "a");
    test_option_index_string_pattern!(find, "abc", "b");
    test_option_index_string_pattern!(find, "abc", "c");
    test_option_index_string_pattern!(find, "abc", "ab");
    test_option_index_string_pattern!(find, "abc", "bc");
    test_option_index_string_pattern!(find, "abc", "abc");
    test_option_index_string_pattern!(find, "abc", "abcd");
    test_option_index_string_pattern!(find, "abc", "d");
    test_option_index_string_pattern!(find, "abc", "dzzzs");
    //test_option_index_string_pattern!(find, "abc", "");
    //test_option_index_string_pattern!(find, "", "abc");
    //test_option_index_string_pattern!(find, "", "");

    test_option_index_char_pattern!(rfind, "abcab", 'a');
    test_option_index_char_pattern!(rfind, "abcab", 'b');
    test_option_index_char_pattern!(rfind, "abcabcd", 'c');
    test_option_index_char_pattern!(rfind, "abc", 'd');
    //test_option_index_char_pattern!(rfind, "", 'b');

    test_option_index_string_pattern!(rfind, "abc", "a");
    test_option_index_string_pattern!(rfind, "abc", "b");
    test_option_index_string_pattern!(rfind, "abc", "c");
    test_option_index_string_pattern!(rfind, "abc", "ab");
    test_option_index_string_pattern!(rfind, "abc", "bc");
    test_option_index_string_pattern!(rfind, "abc", "abc");
    test_option_index_string_pattern!(rfind, "abc", "abcd");
    test_option_index_string_pattern!(rfind, "abc", "d");
    test_option_index_string_pattern!(rfind, "abc", "dzzzs");
    //test_option_index_string_pattern!(rfind, "abc", "");
    //test_option_index_string_pattern!(rfind, "", "abc");
    //test_option_index_string_pattern!(rfind, "", "");
    test_option_index_string_pattern!(rfind, "abcab", "ab");
    test_option_index_string_pattern!(rfind, "abcabd", "ab");
    test_option_index_string_pattern!(rfind, "abcap", "ab");
    test_option_index_string_pattern!(rfind, "abcal", "ab");
    test_option_index_string_pattern!(rfind, "aubuca", "ab");
    test_option_index_string_pattern!(rfind, "auubuc", "ab");
    test_option_index_string_pattern!(rfind, "cca", "ab");
    test_option_index_string_pattern!(rfind, "aaa", "aa");
    test_option_index_string_pattern!(rfind, "aaaa", "aa");
    test_option_index_string_pattern!(rfind, "aaaa", "aaa");
    test_option_index_string_pattern!(rfind, "aaa", "aaa");
    test_option_index_string_pattern!(rfind, "aaa", "aaaa");
}
