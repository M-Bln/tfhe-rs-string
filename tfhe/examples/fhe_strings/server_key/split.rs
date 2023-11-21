use crate::ciphertext::{FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn nth_clear(&self, s: &FheString, n: usize) -> FheAsciiChar {
	match s.padding {
	    Padding::None | Padding::Final if n < s.content.len() => s.content[n].clone(),
	    _ if n >= s.content.len() => FheAsciiChar(self.create_zero()),
	    _ => self.nth_clear_with_padding(&s, n),
	}
    }

    pub fn nth_clear_with_padding(&self, s: &FheString, n: usize) -> FheAsciiChar {
	let mut current_index: RadixCiphertext = self.create_n(u8::MAX);
	let mut result = self.create_zero();
	for c in &s.content {
	    let current_char_non_null : RadixCiphertext =
		self.integer_key.scalar_ne_parallelized(&c.0, 0);
	    self.integer_key.add_assign_parallelized(
		&mut current_index,
		&current_char_non_null,
	    );
	    let right_index = self.integer_key.scalar_eq_parallelized(
		&current_index,
		n as u64,
	    );
	    result = self.integer_key.cmux_parallelized(
		&right_index,
		&c.0,
		&result,
	    )
	}
	FheAsciiChar(result)
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
    fn test_nth_clear() {
	let encrypted_str0 = CLIENT_KEY.encrypt_str_padding("ade", 2).unwrap();
	let encrypted_str = SERVER_KEY.reverse_string_content(&encrypted_str0);
	let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 1);
	assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 100);

	let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 2);
	assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 97);

	let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 0);
	assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 101);
	
	let mut encrypted_char = SERVER_KEY.nth_clear(&encrypted_str, 3);
	assert_eq!(CLIENT_KEY.decrypt_ascii_char(&encrypted_char), 0);
    }
}
