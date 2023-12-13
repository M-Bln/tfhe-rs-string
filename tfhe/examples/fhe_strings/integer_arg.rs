use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::pattern::FheCharPattern;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub trait FheIntegerArg {
    fn splitn_encrypted_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &FheString,
    ) -> FheSplit;

    fn splitn_clear_string_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &str,
    ) -> FheSplit;

    fn splitn_char_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit;

    fn rsplitn_encrypted_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &FheString,
    ) -> FheSplit;

    fn rsplitn_clear_string_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &str,
    ) -> FheSplit;

    fn rsplitn_char_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit;

    fn add_one(&self, server_key: &StringServerKey) -> Self;
}

impl FheIntegerArg for u32 {
    fn splitn_encrypted_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        server_key.split_clear_n_encrypted_string(*self as usize, haystack, pattern)
    }

    fn splitn_clear_string_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &str,
    ) -> FheSplit {
        server_key.split_clear_n_clear_string(*self as usize, haystack, pattern)
    }

    fn splitn_char_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        server_key.split_clear_n_char(*self as usize, haystack, pattern)
    }

    fn rsplitn_encrypted_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        server_key.rsplit_clear_n_encrypted_string(*self as usize, haystack, pattern)
    }

    fn rsplitn_clear_string_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &str,
    ) -> FheSplit {
        server_key.rsplit_clear_n_clear_string(*self as usize, haystack, pattern)
    }

    fn rsplitn_char_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        server_key.rsplit_clear_n_char(*self as usize, haystack, pattern)
    }

    fn add_one(&self, server_key: &StringServerKey) -> Self {
        *self + 1
    }
}

impl FheIntegerArg for RadixCiphertext {
    fn splitn_encrypted_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        server_key.split_encrypted_n_encrypted_string(self, haystack, pattern)
    }

    fn splitn_clear_string_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &str,
    ) -> FheSplit {
        server_key.split_encrypted_n_clear_string(self, haystack, pattern)
    }

    fn splitn_char_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        server_key.split_encrypted_n_char(self, haystack, pattern)
    }

    fn rsplitn_encrypted_string(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &FheString,
    ) -> FheSplit {
        server_key.rsplit_encrypted_n_encrypted_string(self, haystack, pattern)
    }

    fn rsplitn_clear_string_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &str,
    ) -> FheSplit {
        server_key.rsplit_encrypted_n_clear_string(self, haystack, pattern)
    }

    fn rsplitn_char_pattern(
        &self,
        server_key: &StringServerKey,
        haystack: &FheString,
        pattern: &impl FheCharPattern,
    ) -> FheSplit {
        server_key.rsplit_encrypted_n_char(self, haystack, pattern)
    }

    fn add_one(&self, server_key: &StringServerKey) -> Self {
        server_key.integer_key.scalar_add_parallelized(self, 1)
    }
}
