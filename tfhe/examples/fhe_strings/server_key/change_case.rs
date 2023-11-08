use crate::ciphertext::{FheAsciiChar, FheString};
use tfhe::integer::*;

pub const UP_LOW_DISTANCE: u8 = 32;

fn to_upper(c: &FheAsciiChar, server_key: &ServerKey) -> FheAsciiChar {
    FheAsciiChar(server_key.sub_parallelized(
        &c.0,
        &server_key.scalar_mul_parallelized(
            &server_key.bitand_parallelized(
                &server_key.scalar_gt_parallelized(&c.0, 96),
                &server_key.scalar_lt_parallelized(&c.0, 123),
            ),
            UP_LOW_DISTANCE,
        ),
    ))
}

fn to_lower(c: &FheAsciiChar, server_key: &ServerKey) -> FheAsciiChar {
    FheAsciiChar(server_key.add_parallelized(
        &c.0,
        &server_key.scalar_mul_parallelized(
            &server_key.bitand_parallelized(
                &server_key.scalar_gt_parallelized(&c.0, 64),
                &server_key.scalar_lt_parallelized(&c.0, 91),
            ),
            UP_LOW_DISTANCE,
        ),
    ))
}

pub trait ChangeCase {
    fn to_upper(&self, server_key: &ServerKey) -> Self;
    fn to_lower(&self, server_key: &ServerKey) -> Self;
}

impl ChangeCase for FheString {
    fn to_upper(&self, server_key: &ServerKey) -> Self {
        self.iter().map(|c| to_upper(&c, &server_key)).collect()
    }

    fn to_lower(&self, server_key: &ServerKey) -> Self {
        self.iter().map(|c| to_lower(&c, &server_key)).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{decrypt_fhe_string, encrypt_str, gen_keys};
    use crate::server_key::change_case::ChangeCase;
    use lazy_static::lazy_static;
    use tfhe::integer::{RadixClientKey, ServerKey};

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, ServerKey) = gen_keys();
    }

    #[test]
    fn test_to_upper_fhe() {
        let encrypted_str = encrypt_str(&KEYS.0, "aB.").unwrap();
        let encrypted_str_upper = encrypted_str.to_upper(&KEYS.1);
        let decrypted_str_upper = decrypt_fhe_string(&KEYS.0, &encrypted_str_upper).unwrap();
        assert_eq!(&decrypted_str_upper, "AB.");
    }

    #[test]
    fn test_to_lower_fhe() {
        let encrypted_str = encrypt_str(&KEYS.0, "Bc,").unwrap();
        let encrypted_str_upper = encrypted_str.to_lower(&KEYS.1);
        let decrypted_str_upper = decrypt_fhe_string(&KEYS.0, &encrypted_str_upper).unwrap();
        assert_eq!(&decrypted_str_upper, "bc,");
    }
}
