use crate::client_key::StringClientKey;
use crate::server_key::StringServerKey;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, BooleanBlock};
use tfhe::shortint::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    StandardDev, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
};
use tfhe::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MessageModulus,
};

pub const NUMBER_BLOCKS : usize = 4;

#[derive(Clone)]
pub struct FheAsciiChar(pub RadixCiphertext);

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Padding {
    None,
    Final,
    Initial,
    InitialAndFinal,
    Anywhere,
}

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

pub type FheStrLength = ClearOrEncrypted<usize, RadixCiphertext>;
pub type ClearOrEncryptedChar = ClearOrEncrypted<u8, FheAsciiChar>;

#[derive(Clone)]
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

pub const PARAM_MESSAGE_2_CARRY_2_TEST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(1024),
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

pub fn gen_keys_test() -> (StringClientKey, StringServerKey) {
    let num_block = 4;
    match gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_TEST, num_block) {
        (radix_client_key, server_key) => (
            StringClientKey {
                integer_key: radix_client_key,
            },
            StringServerKey {
                integer_key: server_key,
            },
        ),
    }
}

pub fn gen_keys() -> (StringClientKey, StringServerKey) {
    let num_block = 4;
    match gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block) {
        (radix_client_key, server_key) => (
            StringClientKey {
                integer_key: radix_client_key,
            },
            StringServerKey {
                integer_key: server_key,
            },
        ),
    }
}

pub fn gen_keys_big_int() -> (StringClientKey, StringServerKey) {
    let num_block = 8;
    match gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block) {
        (radix_client_key, server_key) => (
            StringClientKey {
                integer_key: radix_client_key,
            },
            StringServerKey {
                integer_key: server_key,
            },
        ),
    }
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

    //    use crate::ciphertext::decrypt_fhe_ascii_vec;

    #[test]
    fn test_decrypt_encrypt_ascii_vec() {
        let encrypted_s = CLIENT_KEY
            .encrypt_ascii_vec(
                &vec![0, 0, 97, 98, 99, 100, 0],
                Padding::InitialAndFinal,
                FheStrLength::Clear(4),
            )
            .unwrap();
        let decrypted_s = CLIENT_KEY.decrypt_fhe_ascii_vec(&encrypted_s);
        println!("the decrypted vec is \"{:?}\"", decrypted_s);
        println!("it is expected to be \"[0,0,97,98,99,100,0]\"");
        assert_eq!(decrypted_s, vec![0, 0, 97, 98, 99, 100, 0]);
    }

    #[test]
    fn test_encrypt() {
        assert!(CLIENT_KEY.encrypt_str("Hello world!").is_ok())
    }

    #[test]
    fn test_decrypt_encrypt() {
        let plain_text = "abc";
        let encrypted_str = CLIENT_KEY.encrypt_str(plain_text).unwrap();
        let decrypted_str = CLIENT_KEY.decrypt_string(&encrypted_str).unwrap();
        println!(
            "the decrypted string is \"{}\", it is expected to be \"{}\"",
            decrypted_str, plain_text,
        )
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
