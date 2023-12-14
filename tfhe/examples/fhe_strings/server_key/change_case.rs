use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::StringServerKey;

pub const UP_LOW_DISTANCE: u8 = 32;

impl StringServerKey {
    pub fn to_uppercase_char(&self, c: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar(self.integer_key.sub_parallelized(
            &c.0,
            &self.integer_key.scalar_mul_parallelized(
                &self.integer_key.bitand_parallelized(
                    &self.integer_key.scalar_gt_parallelized(&c.0, 96),
                    &self.integer_key.scalar_lt_parallelized(&c.0, 123),
                ),
                UP_LOW_DISTANCE,
            ),
        ))
    }

    pub fn to_lowercase_char(&self, c: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar(self.integer_key.add_parallelized(
            &c.0,
            &self.integer_key.scalar_mul_parallelized(
                &self.integer_key.bitand_parallelized(
                    &self.integer_key.scalar_gt_parallelized(&c.0, 64),
                    &self.integer_key.scalar_lt_parallelized(&c.0, 91),
                ),
                UP_LOW_DISTANCE,
            ),
        ))
    }

    pub fn to_lowercase_cmux_char(&self, c: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar(self.integer_key.add_parallelized(
            &c.0,
            &self.integer_key.unchecked_cmux(
                &self.integer_key.bitand_parallelized(
                    &self.integer_key.scalar_gt_parallelized(&c.0, 64),
                    &self.integer_key.scalar_lt_parallelized(&c.0, 91),
                ),
                &self.create_n(UP_LOW_DISTANCE),
                &self.create_zero(),
            ),
        ))
    }

    pub fn to_uppercase(&self, c: &FheString) -> FheString {
        FheString {
            content: c
                .content
                .iter()
                .map(|c| self.to_uppercase_char(c))
                .collect(),
            padding: c.padding,
            length: c.length.clone(),
        }
    }

    pub fn to_lowercase(&self, c: &FheString) -> FheString {
        FheString {
            content: c
                .content
                .iter()
                .map(|c| self.to_lowercase_cmux_char(c))
                .collect(),
            padding: c.padding,
            length: c.length.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_big_int};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

 
    // #[test]
    // fn test_to_upper_fhe() {
    //     let encrypted_str = CLIENT_KEY.encrypt_str("aB.").unwrap();
    //     let encrypted_str_upper = SERVER_KEY.to_uppercase(&encrypted_str);
    //     let decrypted_str_upper = CLIENT_KEY.decrypt_string(&encrypted_str_upper).unwrap();
    //     assert_eq!(&decrypted_str_upper, "AB.");
    // }

    #[test]
    fn test_to_lower_fhe() {
        let encrypted_str = CLIENT_KEY.encrypt_str_random_padding("BC", 0).unwrap();
        let encrypted_str_lower = SERVER_KEY.to_lowercase(&encrypted_str);
        let decrypted_str_lower = CLIENT_KEY.decrypt_string(&encrypted_str_lower).unwrap();
        assert_eq!(&decrypted_str_lower, "bc");
    }

    // #[test]
    // fn test_integer_size() {
    // 	let big_int = CLIENT_KEY.integer_key.encrypt(250 as u32);
    // 	let bigger_int = SERVER_KEY.integer_key.scalar_add_parallelized(&big_int,30);
    // 	assert_eq!(CLIENT_KEY.integer_key.decrypt::<u32>(&bigger_int), 280);
    // }
}
