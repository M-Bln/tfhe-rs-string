use crate::ciphertext::{FheString};
use crate::pattern::FheCharPattern;
use crate::server_key::split::FheSplit;
use crate::server_key::StringServerKey;
use paste::paste;
use tfhe::integer::RadixCiphertext;

macro_rules! generate_fhe_integer_arg_method {
    ( $method_name:ident, $pattern_type:ty ) => {
        fn $method_name(
            &self,
            server_key: &StringServerKey,
            haystack: &FheString,
            pattern: $pattern_type,
        ) -> FheSplit;
    };
}
pub trait FheIntegerArg {
    generate_fhe_integer_arg_method!(splitn_encrypted_string, &FheString);
    generate_fhe_integer_arg_method!(splitn_clear_string_pattern, &str);
    generate_fhe_integer_arg_method!(splitn_char_pattern, &impl FheCharPattern);
    generate_fhe_integer_arg_method!(rsplitn_encrypted_string, &FheString);
    generate_fhe_integer_arg_method!(rsplitn_clear_string_pattern, &str);
    generate_fhe_integer_arg_method!(rsplitn_char_pattern, &impl FheCharPattern);

    //fn repeat_string(&self, server_key: &StringServerKey, s: &FheString) -> FheString;
    fn add_one(&self, server_key: &StringServerKey) -> Self;
    fn to_string(&self) -> String;
}

macro_rules! impl_integer_arg_method {
    ( $method:ident, $pattern_type:ty, $server_key_method:ident, $closure:tt ) => {
        fn $method(
            &self,
            server_key: &StringServerKey,
            haystack: &FheString,
            pattern: $pattern_type,
        ) -> FheSplit {
            server_key.$server_key_method($closure(self), haystack, pattern)
        }
    };
}

macro_rules! impl_splitn_methods {
    ( $inner_method_part:ident, $closure:tt ) => {
        paste! {
            impl_integer_arg_method!(splitn_encrypted_string, &FheString, [<"split_" $inner_method_part "_n_encrypted_string">], $closure);
            impl_integer_arg_method!(splitn_clear_string_pattern, &str, [<"split_" $inner_method_part "_n_clear_string">], $closure);
            impl_integer_arg_method!(splitn_char_pattern, &impl FheCharPattern, [<"split_" $inner_method_part "_n_char">], $closure);
            impl_integer_arg_method!(rsplitn_encrypted_string, &FheString, [<"rsplit_" $inner_method_part "_n_encrypted_string">], $closure);
            impl_integer_arg_method!(rsplitn_clear_string_pattern, &str, [<"rsplit_" $inner_method_part "_n_clear_string">], $closure);
            impl_integer_arg_method!(rsplitn_char_pattern, &impl FheCharPattern, [<"rsplit_" $inner_method_part "_n_char">], $closure);
        }
    };
}

impl FheIntegerArg for u32 {
    impl_splitn_methods!(clear, (|itself: &u32| *itself as usize));
    fn add_one(&self, server_key: &StringServerKey) -> Self {
        *self + 1
    }
    fn to_string(&self) -> String {
        "clear".to_string()
    }

    // fn repeat_string(&self, server_key: &StringServerKey, s: &FheString) -> FheString {
    // 	server_key.repeat_clear(s, *self)
    // }
}

impl FheIntegerArg for usize {
    impl_splitn_methods!(clear, (|itself: &usize| *itself as usize));
    fn add_one(&self, server_key: &StringServerKey) -> Self {
        *self + 1
    }
    fn to_string(&self) -> String {
        "clear".to_string()
    }

    // fn repeat_string(&self, server_key: &StringServerKey, s: &FheString) -> FheString {
    // 	server_key.repeat_clear(s, *self)
    // }
}

impl FheIntegerArg for RadixCiphertext {
    impl_splitn_methods!(encrypted, (|itself| itself));
    fn add_one(&self, server_key: &StringServerKey) -> Self {
        server_key.integer_key.scalar_add_parallelized(self, 1)
    }
    fn to_string(&self) -> String {
        "encrypted".to_string()
    }

    // fn repeat_string(&self, server_key: &StringServerKey, s: &FheString) -> FheString {
    // 	server_key.repeat_encrypted(s, self)
    // }
}
