use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    // pub fn eq(&self, s1: &FheString, s2: &FheString) -> RadixCiphertext{
    // 	// inputs with distinct clear lengths
    // 	match (s1.len, s2.len) {
    // 	    (FheStrLength::Clear(l1), FheStrLength::Clear(l2)) =>
    // 		if l1 != l2 {return self.integer_key.create_trivial_zero_radix(4,1)}
    // 	}
    // 	match (s1.padding, s2.padding) {
    // 	    (Padding::Initial | Padding::InitialAndFinal, Padding::Initial |
    // Padding::InitialAndFinal) => self.eq_init_padding_both(s1, s2), 	    (Padding::Initial |
    // Padding::InitialAndFinal, _) => self.eq_init_padding_first(s1,s2),
    // 	    (_, Padding::Initial | Padding::InitialAndFinal) => self.eq_init_padding_first(s2,s1),
    // 	    _ => self.eq_no_init_padding(s1, s2)
    // 	}
    // }

    // pub fn eq_no_init_padding(s1,s2) {
    // 	let mut result = self.create_true();
    // 	// for n in 0..std::cmp::min(s1.content.len(),s2.content.len()) {
    // 	//     self.integer_key.bitand_assign_parallelized(
    // 	// 	&mut result,
    // 	// 	&self.integer_key.eq_parallelized(s1.content[n].0, s2.content[n].0)
    // 	//     )
    // 	// }
    // 	// for (c1,c2) in std::iter::zip(s1.content.iter(), s2.content.iter()) {
    // 	//     self.integer_key.bitand_assign_parallelized(
    // 	// 	&mut result,
    // 	// 	&self.eq_clear_or_encrypted
    // 	//     )
    // 	// }
    // }

    // pub fn eq_content_no_init_padding(c1 : &Vec<FheAsciiChar>, c2: &Vec<FheAsciiChar>, length:
    // usize) -> RadixCiphertext{ 	let mut result = self.create_true();
    // 	for (c1, c2) in std::iter::zip(c1.iter().take(length), c2.iter().take(length)){
    // 	    self.integer_key.bitand_assign_parallelized(
    // 		&mut result,
    // 		self.integer_key.eq_parallelized(c1,c2),
    // 	    )
    // 	}
    // }

    /// Return the first element encrypting a non null character in content,
    /// replace it in content by an encryption of the null character.
    /// If all character are null, return an encryption of the null character.
    pub fn pop_first_non_zero_char(&self, content: &mut Vec<FheAsciiChar>) -> FheAsciiChar {
        let mut previous_is_padding_zero = self.create_true();
        let mut result = self.create_zero();

        for c in content.iter_mut() {
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
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{
        decrypt_fhe_string, encrypt_ascii_vec, gen_keys, FheStrLength, Padding,
    };
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, StringServerKey) = gen_keys();
    }

    #[test]
    fn test_pop_first_non_zero_char() {
        let mut encrypted_str = encrypt_ascii_vec(
            &KEYS.0,
            &vec![0, 97, 98, 0],
            Padding::InitialAndFinal,
            FheStrLength::Clear(1),
        )
        .unwrap();
        let poped_char = KEYS.1.pop_first_non_zero_char(&mut encrypted_str.content);
        let decrypted_poped_char = KEYS.0.decrypt::<u8>(&poped_char.0);
        assert_eq!(decrypted_poped_char, 97);
        let decrypted_string = decrypt_fhe_string(&KEYS.0, &encrypted_str).unwrap();
        assert_eq!(decrypted_string, "b");
    }
}
