use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;



pub struct FheAsciiChar(RadixCiphertext);

pub type FheString = Vec<FheAsciiChar>;

pub fn encrypt_ascii_vec(
    client_key: &RadixClientKey,
    utf8_vec: &Vec<u8>,
) -> Result<FheString, Box<dyn std::error::Error>> {
    if utf8_vec.iter().any(|c| !c.is_ascii()) {
	return Err("content contains non-ascii characters".into())
    }
    Ok(utf8_vec.iter()
               .map(|byte| FheAsciiChar(client_key.encrypt(*byte as u64)))
               .collect())
}

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
        .collect::<Vec<FheAsciiChar>>())
}

pub fn decrypt_fhe_ascii_vec(
    client_key: &RadixClientKey,
    s: &FheString,
) -> Vec<u8> {
    s.iter()
     .map(|crypted_char| client_key.decrypt::<u8>(&crypted_char.0))
     .collect::<Vec<u8>>()
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


/// Trim the initial and final '\0' bytes from a Vec<u8>, return a &str
pub fn str_from_null_padded_utf8(utf8_src: &Vec<u8>) -> Result<&str, std::str::Utf8Error> {
    let range_start = utf8_src.iter()
        .position(|&c| c != b'\0')
        .unwrap_or(utf8_src.len()); // default to length if only `\0` are present
    let range_end = utf8_src[range_start..utf8_src.len()].iter()
	.position(|&c| c == b'\0')
	.unwrap_or(utf8_src.len()); // default to length if no trailing '\0'
    ::std::str::from_utf8(&utf8_src[range_start..(range_end + range_start)])
}

/// Produce a Vec<u8> of length length from str by adding trailing '\0'
/// if str.length() > length, the end of the string is truncated. 
pub fn null_padded_utf8_from_str(s: &str, length : usize ) -> Vec<u8> {
    let mut result : Vec<u8> = s.as_bytes().to_vec();
    if s.len() > length {
	result[0..length].to_vec()
    } else {
	result.append(&mut vec![0;length - s.len()]);
	result
    }
}


#[cfg(test)]
mod tests {
    use crate::ciphertext::gen_keys;
    use crate::ciphertext::encrypt_ascii_vec;

    #[test]
    fn test_encrypt_ascii_vec() {
	let (client_key, _) = gen_keys();
	assert!(encrypt_ascii_vec(&client_key, &vec![0,0,97,98,99,100,0]).is_ok());
	assert!(encrypt_ascii_vec(&client_key, &vec![0,0,0xc3,0x28,0,0]).is_err());
    }

    use crate::ciphertext::decrypt_fhe_ascii_vec;

    #[test]
    fn test_decrypt_encrypt_ascii_vec(){
	let (client_key, _) = gen_keys();
	match encrypt_ascii_vec(&client_key, &vec![0,0,97,98,99,100,0]) {
	    Ok(encrypted_s) => {
		let decrypted_s = decrypt_fhe_ascii_vec(&client_key, &encrypted_s);
		println!("the decrypted vec is \"{:?}\"", decrypted_s);
		println!("it is expected to be \"[0,0,97,98,99,100,0]\"");
		assert_eq!(decrypted_s,vec![0,0,97,98,99,100,0]);
	    },
	    Err(_) => panic!("encryption failed"),
	}
    } 
    
    use crate::ciphertext::encrypt_str;
   
    #[test]
    fn test_encrypt() {
	let (client_key, _) = gen_keys();
	if !encrypt_str(&client_key, "Hello world!").is_ok() {
	    panic!("encryption failed");
	}
    }

    use crate::ciphertext::decrypt_fhe_string;
    
    #[test]
    fn test_decrypt_encrypt(){
	let (client_key, _) = gen_keys();
	let try_encrypt_decrypt : Result<String, Box<dyn std::error::Error>>
	    = encrypt_str(&client_key, "abc").map_or_else(|e| Err(e),
							  |encrypted_s| decrypt_fhe_string(&client_key, &encrypted_s));
	match  try_encrypt_decrypt {
	    Ok(decrypted_s) => println!("the decrypted string is \"{}\", it is expected to be \"abc\"", decrypted_s),
	    Err(_) => panic!("encryption / decryption failed"),
	}
    }

    use crate::ciphertext::str_from_null_padded_utf8;

    #[test]
    fn test_str_from_null_padded_utf8(){
	let valid_utf8_src = vec![0,0,0,0,97,98,99,100,0,0,0,0,0,0];
	let s = str_from_null_padded_utf8(&valid_utf8_src).unwrap();
	assert!(s.eq("abcd"));

	let invalid_utf8_src = vec![0,0,0xc3,0x28,0,0];
	assert!(str_from_null_padded_utf8(&invalid_utf8_src).is_err());
    }

    use crate::ciphertext::null_padded_utf8_from_str;

    #[test]
    fn test_null_padded_utf8_from_str(){
	let padded_utf8 = null_padded_utf8_from_str("abc", 5);
	assert_eq!(padded_utf8, vec![97,98,99,0,0]);

	let truncated_utf8 = null_padded_utf8_from_str("abcdef",3);
	assert_eq!(truncated_utf8, vec![97,98,99]);
    }
}
