use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;


pub struct FheAsciiChar(RadixCiphertext);

pub type FheString = Vec<FheAsciiChar>;


pub fn encrypt_str(
    client_key: &RadixClientKey,
    s: &str,
) -> Result<FheString, Box<dyn std::error::Error>> {
    if !s.is_ascii() {
	return Err("content contains non-ascii characters".into())
    }
    Ok(s.as_bytes()
        .iter()
        .map(|byte| FheAsciiChar(client_key.encrypt(*byte as u64)))
        .collect())
}

pub fn decrypt_fhe_string(
    client_key: &RadixClientKey,
    s: &FheString,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(s.iter()
		       .map(|cipher_char| client_key.decrypt::<u8>(&cipher_char.0))
		       .collect())?)
}

pub fn gen_keys() -> (RadixClientKey, ServerKey){
    let num_block = 4;
    gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block)
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys;
    use crate::ciphertext::encrypt_str;
    use crate::ciphertext::decrypt_fhe_string;

    #[test]
    fn test_encrypt() {
	let (client_key, _) = gen_keys();
	if !encrypt_str(&client_key, "Hello world!").is_ok() {
	    panic!("encryption failed");
	}
    }

    #[test]
    fn test_decrypt_encrypt(){
	let (client_key, _) = gen_keys();
	if let Ok(encrypted_s) = encrypt_str(&client_key, "Hello world!"){
	    if let Ok(decrypted_s) = decrypt_fhe_string(&client_key, &encrypted_s){
		println!("the decrypted string is \"{}\"", decrypted_s);
		println!("it is expected to be \"Hello world\"");
		assert!(decrypted_s.eq("Hello world!"));
	    } else {
		panic!("decryption failed");
	    };
	} else {
	    panic!("encryption failed");
	}
    }
}
