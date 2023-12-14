use crate::ciphertext::FheStrLength;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    /// Returns the sum of the length l1 and l2.
    pub fn add_length(&self, l1: &FheStrLength, l2: &FheStrLength) -> FheStrLength {
        match (&l1, &l2) {
            (FheStrLength::Encrypted(encrypted_l1), l2) => self.add_radix_length(l2, encrypted_l1),
            (l1, FheStrLength::Encrypted(encrypted_l2)) => self.add_radix_length(l1, encrypted_l2),
            (FheStrLength::Clear(clear_l1), FheStrLength::Clear(clear_l2)) => {
                FheStrLength::Clear(*clear_l1 + *clear_l2)
            }
        }
    }

    /// Adds a clear integer n to the length of an encrypted string and returns an `FheStrLength`.
    pub fn add_scalar_to_length(&self, fhe_length: &FheStrLength, n: usize) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => FheStrLength::Clear(clear_length + n),
            FheStrLength::Encrypted(encrypted_length) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_add_parallelized(encrypted_length, n as u32),
            ),
        }
    }

    /// Adds an encrypted integer n to the length of an encrypted string and returns an
    /// `FheStrLength`.
    pub fn add_radix_to_length(
        &self,
        fhe_length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_add_parallelized(n, *clear_length as u32),
            ),
            FheStrLength::Encrypted(encrypted_length) => {
                FheStrLength::Encrypted(self.integer_key.add_parallelized(encrypted_length, n))
            }
        }
    }

    /// Substracts an encrypted integer n to the length of an encrypted string and returns an
    /// `FheStrLength`.
    pub fn sub_radix_to_length(
        &self,
        fhe_length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => {
                let result_positive = self
                    .integer_key
                    .scalar_le_parallelized(n, *clear_length as u32);
                let radix_result = self.integer_key.cmux_parallelized(
                    &result_positive,
                    &self
                        .integer_key
                        .sub_parallelized(&self.create_n(*clear_length as u8), n),
                    &self.create_zero(),
                );
                FheStrLength::Encrypted(radix_result)
            }
            FheStrLength::Encrypted(encrypted_length) => {
                let result_positive = self.integer_key.le_parallelized(n, encrypted_length);
                let radix_result = self.integer_key.cmux_parallelized(
                    &result_positive,
                    &self.integer_key.sub_parallelized(encrypted_length, n),
                    &self.create_zero(),
                );
                FheStrLength::Encrypted(radix_result)
            }
        }
    }

    /// Multiplies the length of an encrypted string by an encrypted integer and returns an
    /// `FheStrLength`.
    pub fn mult_length_by_radix(
        &self,
        fhe_length: &FheStrLength,
        n: &RadixCiphertext,
    ) -> FheStrLength {
        match fhe_length {
            FheStrLength::Clear(clear_length) => FheStrLength::Encrypted(
                self.integer_key
                    .scalar_mul_parallelized(n, *clear_length as u32),
            ),
            FheStrLength::Encrypted(encrypted_length) => {
                FheStrLength::Encrypted(self.integer_key.mul_parallelized(encrypted_length, n))
            }
        }
    }
}
