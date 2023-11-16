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
                .map(|c| self.to_lowercase_char(c))
                .collect(),
            padding: c.padding,
            length: c.length.clone(),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::ciphertext::{gen_keys};
//     use crate::server_key::StringServerKey;
//     use lazy_static::lazy_static;
//     use tfhe::integer::RadixClientKey;

//     lazy_static! {
//         pub static ref KEYS: (RadixClientKey, StringServerKey) = gen_keys();
//     }

//     #[test]
//     fn test_to_upper_fhe() {
//         let encrypted_str = encrypt_str(&KEYS.0, "aB.").unwrap();
//         let encrypted_str_upper = KEYS.1.to_uppercase(&encrypted_str);
//         let decrypted_str_upper = decrypt_fhe_string(&KEYS.0, &encrypted_str_upper).unwrap();
//         assert_eq!(&decrypted_str_upper, "AB.");
//     }

//     #[test]
//     fn test_to_lower_fhe() {
//         let encrypted_str = encrypt_str(&KEYS.0, "Bc,").unwrap();
//         let encrypted_str_lower = KEYS.1.to_lowercase(&encrypted_str);
//         let decrypted_str_lower = decrypt_fhe_string(&KEYS.0, &encrypted_str_lower).unwrap();
//         assert_eq!(&decrypted_str_lower, "bc,");
//     }
// }
