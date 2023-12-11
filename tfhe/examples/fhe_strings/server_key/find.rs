use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn find(
        &self,
        haystack: &FheString,
        pattern: &impl FhePattern,
    ) -> (RadixCiphertext, RadixCiphertext) {
        pattern.find_in(self, haystack)
    }

    pub fn rfind(
        &self,
        haystack: &FheString,
        pattern: &impl FhePattern,
    ) -> (RadixCiphertext, RadixCiphertext) {
        pattern.rfind_in(self, haystack)
    }

    pub fn find_char(
        &self,
        s: &FheString,
        char_pattern: &impl FheCharPattern,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return (zero.clone(), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match: RadixCiphertext = char_pattern.fhe_eq(self, &s.content[n]);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn rfind_char(
        &self,
        s: &FheString,
        char_pattern: &impl FheCharPattern,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match s.length {
            FheStrLength::Clear(length) if length == 0 => return (zero.clone(), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) =
            (self.initial_index_rfind_char(&s.length), zero.clone());
        for n in (0..s.content.len()).rev() {
            let current_match: RadixCiphertext = char_pattern.fhe_eq(self, &s.content[n]);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    // pub fn find(
    // 	&self,
    // 	s: &FheString,
    // 	pattern: &impl FhePattern,
    // ) -> (RadixCiphertext, RadixCiphertext) {

    // }

    pub fn find_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }

        match (s.padding, pattern.padding) {
            (Padding::Anywhere, Padding::None | Padding::Final) => {
                self.connected_find_unpadded_string(&self.remove_initial_padding(s), pattern)
            }
            (Padding::Anywhere, _) => self.connected_find_unpadded_string(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(pattern),
            ),
            (_, Padding::None | Padding::Final) => self.connected_find_unpadded_string(s, pattern),
            _ => self.connected_find_unpadded_string(s, &self.remove_initial_padding(pattern)),
        }
    }

    pub fn find_clear_string(
        &self,
        s: &FheString,
        pattern: &str,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), zero),
            (content_length, pattern_length) if pattern_length > content_length => {
                return (zero.clone(), zero)
            }
            _ => (),
        }

        match s.padding {
            Padding::Anywhere => {
                self.connected_find_clear_string(&self.remove_initial_padding(s), pattern)
            }
            _ => self.connected_find_clear_string(s, pattern),
        }
    }

    pub fn rfind_clear_string(
        &self,
        s: &FheString,
        pattern: &str,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), zero),
            (content_length, pattern_length) if pattern_length > content_length => {
                return (zero.clone(), zero)
            }
            _ => (),
        }

        match s.padding {
            Padding::Anywhere => {
                self.connected_rfind_clear_string(&self.remove_initial_padding(s), pattern)
            }
            _ => self.connected_rfind_clear_string(s, pattern),
        }
    }

    pub fn connected_find_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn connected_find_clear_string(
        &self,
        s: &FheString,
        pattern: &str,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);
            //            let current_match = self.starts_with_encrypted_vec(&s.content[n..],
            // pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn connected_rfind_clear_string(
        &self,
        s: &FheString,
        pattern: &str,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let mut index = self.initial_index_rfind(&s.length);
        if pattern.len() == 0 {
            return (self.create_true(), index);
        }
        let mut found = self.create_zero();
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            //let current_match = self.starts_with_vec_clear(&s.content[n..],  pattern);
            let current_match = pattern.is_prefix_of_slice(self, &s.content[n..]);

            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    //Should be called with `pattern.padding` either `Padding::None` or `Padding::Final`.
    pub fn find_from_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn find_clear_from_final_padding(
        &self,
        s: &FheString,
        pattern: &str,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.len()) {
            (0, 0) => return (self.create_true(), from.clone()),
            (0, _) => return (zero.clone(), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &pattern.is_prefix_of_slice(self, &s.content[n..]),
                //                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn find_char_from_final_padding(
        &self,
        s: &FheString,
        pattern: &impl FheCharPattern,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        if s.content.len() == 0 {
            return (zero.clone(), zero);
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &pattern.is_prefix_of_slice(self, &s.content[n..]),
                //                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            let increment_index = self.increment_index(s, n, &found);
            self.integer_key
                .add_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn find_from_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (self.create_true(), zero),
            (0, _) => return (self.eq_clear_char(&pattern.content[0], 0), zero),
            _ => (),
        }
        let (mut index, mut found): (RadixCiphertext, RadixCiphertext) = (zero.clone(), zero);
        for n in 0..s.content.len() {
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_le_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
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

    pub fn rfind_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
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
                self.connected_rfind_unpadded_string(&self.remove_initial_padding(s), pattern)
            }
            (Padding::Anywhere, _) => self.connected_rfind_unpadded_string(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(pattern),
            ),
            (_, Padding::None | Padding::Final) => self.connected_rfind_unpadded_string(s, pattern),
            _ => self.connected_rfind_unpadded_string(s, &self.remove_initial_padding(pattern)),
        }
    }

    pub fn connected_rfind_unpadded_string(
        &self,
        s: &FheString,
        pattern: &FheString,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let initial_index = self.initial_index_rfind(&s.length);
        let mut index = initial_index.clone();
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.starts_with_encrypted_vec(&s.content[n..], pattern);
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);

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

    pub fn rfind_from_final_padding(
        &self,
        s: &FheString,
        pattern: &FheString,
        to: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero: RadixCiphertext = self.create_zero();
        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.increment_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(to, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);

            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn rfind_from_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (from_greater_than_zero, zero),
            (0, _) => {
                return (
                    self.integer_key.bitand_parallelized(
                        &self.eq_clear_char(&pattern.content[0], 0),
                        &from_greater_than_zero,
                    ),
                    zero,
                )
            }
            _ => (),
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
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

    // is called with non empty pattern str
    pub fn rfind_clear_from_final_padding(
        &self,
        s: &FheString,
        pattern: &str,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
//        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
	if s.content.len() < pattern.len() {return (zero.clone(), zero)}

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
		&pattern.is_prefix_of_slice(self, &s.content[n..]),
//                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    pub fn rfind_char_from_final_padding(
        &self,
        s: &FheString,
        pattern: &impl FheCharPattern,
        from: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
//        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
	if s.content.len() == 0 {return (zero.clone(), zero)}

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
		&pattern.fhe_eq(self, &s.content[n]),
//                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_gt_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        (found, index)
    }

    
    pub fn rfind_from_to_final_padding_allow_empty_pattern(
        &self,
        s: &FheString,
        pattern: &FheString,
        from: &RadixCiphertext,
        to: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let from_greater_than_zero = self.integer_key.scalar_gt_parallelized(from, 0);
        let zero: RadixCiphertext = self.create_zero();
        match (s.content.len(), pattern.content.len()) {
            (0, 0) => return (from_greater_than_zero, zero),
            (0, _) => {
                return (
                    self.integer_key.bitand_parallelized(
                        &self.eq_clear_char(&pattern.content[0], 0),
                        &from_greater_than_zero,
                    ),
                    zero,
                )
            }
            _ => (),
        }

        let mut index = self.initial_index_rfind(&s.length);
        let mut found = zero;
        for n in (0..s.content.len()).rev() {
            let increment_index = self.rincrement_index(s, n, &found);
            let current_match = self.integer_key.bitand_parallelized(
                &self.starts_with_encrypted_vec(&s.content[n..], pattern),
                &self.integer_key.scalar_ge_parallelized(from, n as u64),
            );
            self.integer_key
                .bitor_assign_parallelized(&mut found, &current_match);
            self.integer_key
                .sub_assign_parallelized(&mut index, &increment_index);
        }
        index = self.integer_key.cmux_parallelized(
            &self.is_empty_encrypted(pattern),
            &self.min_length_radix(&s.length, from),
            &index,
        );
        (found, index)
    }

    // pub fn rfind_from_final_padding_allow_empty_pattern(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    //     to: &RadixCiphertext,
    // ) -> (RadixCiphertext, RadixCiphertext) {
    //     let zero: RadixCiphertext = self.create_zero();
    //     let mut index = self.initial_index_rfind(&s.length);
    //     let mut found = zero;
    //     for n in (0..=s.content.len()).rev() {
    //         let current_match = self.integer_key.bitand_parallelized(
    //             &self.starts_with_encrypted_vec(&s.content[n..], pattern),
    //             &self.integer_key.scalar_gt_parallelized(to, n as u64),
    //         );
    //         self.integer_key
    //             .bitor_assign_parallelized(&mut found, &current_match);
    // 	    let increment_index = self.increment_index(s, n, &found);
    //         self.integer_key
    //             .sub_assign_parallelized(&mut index, &increment_index);
    //     }
    //     (found, index)
    // }

    pub fn min_length_radix(&self, length: &FheStrLength, to: &RadixCiphertext) -> RadixCiphertext {
        match length {
            FheStrLength::Clear(clear_length) => self
                .integer_key
                .scalar_min_parallelized(to, *clear_length as u64),
            FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(to, l),
        }
    }

    // pub fn min_length_radix_mi(&self, length: &FheStrLength, to: &RadixCiphertext) ->
    // RadixCiphertext {     match length {
    //         FheStrLength::Clear(clear_length) => self
    //             .integer_key
    //             .scalar_min_parallelized(to, *clear_length as u64),
    //         FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(to, l),
    //     }
    // }

    // pub fn rfind_from_final_padding_allow_empty_pattern(
    //     &self,
    //     s: &FheString,
    //     pattern: &FheString,
    //     to: &RadixCiphertext,
    // ) -> (RadixCiphertext, RadixCiphertext) {
    //     let zero: RadixCiphertext = self.create_zero();
    //     let mut found = self.is_empty_encrypted(&pattern);
    //     let positive_to = self.integer_key.scalar_max_parallelized(to, 0);
    //     let upper_bound: RadixCiphertext = match &s.length {
    //         FheStrLength::Clear(clear_length) => self
    //             .integer_key
    //             .scalar_min_parallelized(&positive_to, *clear_length as u64),
    //         FheStrLength::Encrypted(l) => self.integer_key.min_parallelized(&positive_to, l),
    //     };

    //     let mut index = self.integer_key.cmux_parallelized(
    //         &found,
    //         &upper_bound,
    //         &self.initial_index_rfind(&s.length),
    //     );

    //     for n in (0..s.content.len()).rev() {
    //         let increment_index = self.increment_index(s, n, &found);

    //         let current_match = self.integer_key.bitand_parallelized(
    //             &self.starts_with_encrypted_vec(&s.content[n..], pattern),
    //             &self.integer_key.scalar_gt_parallelized(to, n as u64),
    //         );
    //         self.integer_key
    //             .bitor_assign_parallelized(&mut found, &current_match);

    //         self.integer_key
    //             .sub_assign_parallelized(&mut index, &increment_index);
    //     }
    //     (found, index)
    // }

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

    pub fn increment_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        match s.padding {
            Padding::None | Padding::Final => self.integer_key.scalar_eq_parallelized(&found, 0),
            _ => self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_eq_parallelized(&found, 0),
                &self
                    .integer_key
                    .scalar_ne_parallelized(&s.content[content_index].0, 0),
            ),
        }
    }

    pub fn rincrement_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.integer_key.bitand_parallelized(
            &self.integer_key.scalar_eq_parallelized(&found, 0),
            &self
                .integer_key
                .scalar_ne_parallelized(&s.content[content_index].0, 0),
        )
    }

    pub fn decrement_index(
        &self,
        s: &FheString,
        content_index: usize,
        found: &RadixCiphertext,
    ) -> RadixCiphertext {
        match s.padding {
            Padding::None | Padding::Initial => self.integer_key.scalar_eq_parallelized(&found, 0),
            _ if content_index > s.content.len() => {
                self.integer_key.scalar_eq_parallelized(&found, 0)
            }
            _ => self.integer_key.bitand_parallelized(
                &self.integer_key.scalar_eq_parallelized(&found, 0),
                &self
                    .integer_key
                    .scalar_ne_parallelized(&s.content[content_index].0, 0),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_test};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_option_index_char_pattern, test_option_index_string_pattern};
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    // macro_rules! unit_test_char{
    // 	($method: ident, $string_arg: expr, $pattern_arg: expr, char , $result_type: ty,
    // $string_padding: expr) => { 	    #[test]
    // 	    fn test_name!($method, $string_arg, $pattern_arg, char, $string_padding) () {
    // 		let std_result = $string_arg.$method($pattern_arg);
    //             let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,
    // $string_padding).unwrap();             let fhe_result = SERVER_KEY.$method(&encrypted_s,
    // &$pattern_arg); 		compare_result!($result_type, std_result, fhe_result);
    // 	    }
    // 	};

    // 	($method: ident, $string_arg: expr, $pattern_arg: expr, FheChar, $result_type: ty,
    // $string_padding: expr) => { 	    #[test]
    // 	    fn test_name!($method, $string_arg, $pattern_arg, FheChar, $string_padding) () {
    // 		let std_result = $string_arg.$method($pattern_arg);
    //             let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,
    // $string_padding).unwrap(); 		let encrypted_pattern =
    // CLIENT_KEY.encrypt_ascii_char($pattern_arg as u8);             let fhe_result =
    // SERVER_KEY.$method(&encrypted_s, &$pattern_arg); 		compare_result!($result_type,
    // std_result, fhe_result); 	    }
    // 	};
    // }

    // macro_rules! test_string {
    //     ($method: ident, $string_arg: expr, $pattern_arg: expr) => {
    //         unit_test_char!($method, $string_arg, $pattern_arg, 0, 0);
    //         unit_test_char!($method, $string_arg, $pattern_arg, 2, 0);
    //         unit_test_char!($method, $string_arg, $pattern_arg, 0, 2);
    //         unit_test_char!($method, $string_arg, $pattern_arg, 2, 2);
    //     };
    // }
    // macro_rules! unit_test_string {
    // 	($method: ident, $string_arg: expr, $pattern_arg: expr, &str, $result_type: ty,
    // $string_padding: expr) => { 	    #[test]
    // 	    fn test_name!($method, $string_arg, $pattern_arg, &str, $string_padding) () {
    // 		let std_result = $string_arg.$method($pattern_arg);
    //             let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,
    // $string_padding).unwrap();             let fhe_result = SERVER_KEY.$method(&encrypted_s,
    // &$pattern_arg); 		compare_result!($result_type, std_result, fhe_result);
    // 	    }
    // 	};
    // 	($method: ident, $string_arg: expr, $pattern_arg: expr, FheString, $result_type: ty,
    // $string_padding: expr, $pattern_padding: expr) => { 	    #[test]
    // 	    fn test_name!($method, $string_arg, $pattern_arg, FheChar, $string_padding,
    // $pattern_padding) () { 		let std_result = $string_arg.$method($pattern_arg);
    //             let encrypted_s = CLIENT_KEY.encrypt_str_padding(&$string_arg,
    // $string_padding).unwrap(); 		let encrypted_pattern =
    // CLIENT_KEY.encrypt_str_padding($pattern_arg as u8, $pattern_padding);             let
    // fhe_result = SERVER_KEY.$method(&encrypted_s, &$pattern_arg); 		compare_result!
    // ($result_type, std_result, fhe_result); 	    }
    // 	};
    // }

    test_option_index_char_pattern!(find, "abc", 'a');
    test_option_index_char_pattern!(find, "abc", 'b');
    test_option_index_char_pattern!(find, "abc", 'c');
    test_option_index_char_pattern!(find, "abc", 'd');
    test_option_index_char_pattern!(find, "", 'b');

    //    write_test_char!(find);

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
    test_option_index_string_pattern!(find, "abc", "");
    test_option_index_string_pattern!(find, "", "abc");
    test_option_index_string_pattern!(find, "", "");

    test_option_index_char_pattern!(rfind, "abcab", 'a');
    test_option_index_char_pattern!(rfind, "abcab", 'b');
    test_option_index_char_pattern!(rfind, "abcabcd", 'c');
    test_option_index_char_pattern!(rfind, "abc", 'd');
    test_option_index_char_pattern!(rfind, "", 'b');

    test_option_index_string_pattern!(rfind, "abc", "a");
    test_option_index_string_pattern!(rfind, "abc", "b");
    test_option_index_string_pattern!(rfind, "abc", "c");
    test_option_index_string_pattern!(rfind, "abc", "ab");
    test_option_index_string_pattern!(rfind, "abc", "bc");
    test_option_index_string_pattern!(rfind, "abc", "abc");
    test_option_index_string_pattern!(rfind, "abc", "abcd");
    test_option_index_string_pattern!(rfind, "abc", "d");
    test_option_index_string_pattern!(rfind, "abc", "dzzzs");
    test_option_index_string_pattern!(rfind, "abc", "");
    test_option_index_string_pattern!(rfind, "", "abc");
    test_option_index_string_pattern!(rfind, "", "");
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
