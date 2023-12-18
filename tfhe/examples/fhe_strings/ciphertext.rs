use crate::client_key::StringClientKey;
use crate::server_key::StringServerKey;
use tfhe::integer::{gen_keys_radix, RadixCiphertext};
use tfhe::shortint::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    StandardDev, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
};
use tfhe::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MessageModulus,
};

/// Number of blocks of RadixCiphertext. 4 corresponds to integer of 8 bits. Must be modify to allow
/// correctly work with string of length larger than 8 bits.
pub const NUMBER_BLOCKS: usize = 4;

#[derive(Clone)]
/// Encrypted ascii character are RadixCiphertext encryption of the corresponding integer
pub struct FheAsciiChar(pub RadixCiphertext);

#[derive(Copy, Clone, PartialEq, Debug)]
/// Padding zeros are allowed anywhere in the content of an FheString, they are ignored after
/// decryption. They allow to obfuscate the string length.
pub enum Padding {
    None,
    Final,
    Initial,
    InitialAndFinal,
    Anywhere,
}

/// Order the padding from the less inconvenient (None) to most inconvenient (Anywhere)
impl PartialOrd for Padding {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (x, y) if x == y => Some(std::cmp::Ordering::Equal),
            (Padding::None, _) | (_, Padding::Anywhere) => Some(std::cmp::Ordering::Less),
            (Padding::Final, Padding::Initial) | (Padding::Initial, Padding::Final) => None,
            (Padding::Final | Padding::Initial, Padding::InitialAndFinal) => {
                Some(std::cmp::Ordering::Less)
            }
            _ => Some(std::cmp::Ordering::Greater),
        }
    }
}

#[derive(Clone)]
pub enum ClearOrEncrypted<T, U> {
    Clear(T),
    Encrypted(U),
}

/// The length of an encrypted string can be obfuscated in the presence of padding zeros. In this
/// case it is stored as an encrypted integer.
pub type FheStrLength = ClearOrEncrypted<usize, RadixCiphertext>;
pub type ClearOrEncryptedChar = ClearOrEncrypted<u8, FheAsciiChar>;

#[derive(Clone)]
/// The main type to store an encrypted string.
/// Its content is a vector of FheAsciiChar, eventually containing some padding zeros, ignored after
/// decryption. The location of padding zeros is indicated by `padding`. The length of the string
/// (actual length after decryption and ignoring padding zeros) is stored either as a clear or as an
/// encrypted integer.
pub struct FheString {
    pub content: Vec<FheAsciiChar>,
    pub padding: Padding,
    pub length: FheStrLength,
}

impl FheString {
    pub fn len(&self) -> &FheStrLength {
        &self.length
    }
}

/// Non secure cryptographic parameters to allow fast tests.
pub const PARAM_MESSAGE_2_CARRY_2_TEST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

/// Generates a pair (client_key, server_key) with non secure cryptographic parameters to allow fast
/// test.
pub fn gen_keys_test() -> (StringClientKey, StringServerKey) {
    let num_block = 4;
    let (radix_client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_TEST, num_block);
    (
        StringClientKey {
            integer_key: radix_client_key,
        },
        StringServerKey {
            integer_key: server_key,
        },
    )
}

/// Generate a pair (client_key, server_key) with secure cryptographic parameters and NUMBER_BLOCKS
/// blocks.
pub fn gen_keys() -> (StringClientKey, StringServerKey) {
    gen_keys_number_blocks(NUMBER_BLOCKS)
}

/// Generate a pair (client_key, server_key) with secure cryptographic parameters and specified
/// number of blocks. Should be at least 4 in order to work with ascii chars. Should be larger than
/// 4 to works with string of length larger than 8 bits.
pub fn gen_keys_number_blocks(num_blocks: usize) -> (StringClientKey, StringServerKey) {
    let (radix_client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    (
        StringClientKey {
            integer_key: radix_client_key,
        },
        StringServerKey {
            integer_key: server_key,
        },
    )
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

    #[test]
    fn test_encrypt_ascii_vec() {
        assert!(CLIENT_KEY
            .encrypt_ascii_vec(
                &vec![0, 0, 97, 98, 99, 100, 0],
                Padding::InitialAndFinal,
                FheStrLength::Clear(4)
            )
            .is_ok());
        assert!(CLIENT_KEY
            .encrypt_ascii_vec(
                &vec![0, 0, 0xc3, 0x28, 0, 0],
                Padding::InitialAndFinal,
                FheStrLength::Clear(2)
            )
            .is_err());
    }

    #[test]
    fn test_encrypt() {
        assert!(CLIENT_KEY.encrypt_str("Hello world!").is_ok())
    }

    #[test]
    fn test_string_from_padded_utf8() {
        let valid_utf8_src = vec![0, 0, 0, 0, 97, 98, 99, 100];
        let s = StringClientKey::string_from_padded_vec(valid_utf8_src).unwrap();
        assert!(s.eq("abcd"));

        let invalid_utf8_src = vec![0, 0, 0xc3, 0x28, 0, 0];
        assert!(StringClientKey::string_from_padded_vec(invalid_utf8_src).is_err());
    }

    #[test]
    fn test_null_padded_utf8_from_str() {
        let padded_utf8 = StringClientKey::null_padded_vec_from_str("abc", 2);
        assert_eq!(padded_utf8, vec![97, 98, 99, 0, 0]);

        let truncated_utf8 = StringClientKey::null_padded_vec_from_str("abc", 0);
        assert_eq!(truncated_utf8, vec![97, 98, 99]);
    }
}
