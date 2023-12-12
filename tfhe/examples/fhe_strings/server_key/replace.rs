use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use crate::pattern::FhePattern;

impl StringServerKey {
    pub fn replace(&self, s: &FheString, old_pattern: &impl FhePattern, new: &FheString) -> FheString {
	let splited_s = self.split(s, old_pattern);
	let mut result = FheString {
	    content: Vec::new(),
	    length: ClearOrEncrypted::Clear(0),
	    padding: Padding::None,
	};
	let number_replacement = self.integer_key.cmux_parallelized(
	    &self.integer_key.scalar_ne_parallelized(&splited_s.number_parts, 0),
	    &self.integer_key.scalar_sub_parallelized(&splited_s.number_parts, 1),
	    &self.create_zero(),
	);
	let mut total_length = FheStrLength::Clear(0);
	for part in splited_s.parts.iter() {
	    result = self.add(result, part);
	    result = self.add(result, new);
	    match &part.len() {
		FheStrLength::Clear(clear_length) => {
		    total_length = self.add_scalar_to_length(&total_length, *clear_length);  
		},
		FheStrLength::Encrypted(encrypted_length) => {
		    total_length = self.add_radix_to_length(&total_length, encrypted_length);
		},
	    }
	}

	let total_length = self.add_length(&total_length, &self.mult_length_by_radix(new.len(), &number_replacement));
	match result.padding {
	    Padding::None | Padding::Final => self.erase_after(result, total_length) ,
	    _ => self.erase_after(self.remove_initial_padding(&result), total_length) ,
	}
    }

    // assume s has final padding at worst
    pub fn erase_after(&self, mut s: FheString, result_length: FheStrLength) -> FheString{
	let zero = self.create_zero();
	s.length = result_length;
	match &s.length {
	    FheStrLength::Encrypted(encrypted_length) => {
		for i in 0..s.content.len() {
		    s.content[i] = FheAsciiChar(self.integer_key.cmux_parallelized(
			&self.integer_key.scalar_le_parallelized(&encrypted_length, i as u32),
			&zero,
			&s.content[i].0,
		    ));
		}
	    },
	    FheStrLength::Clear(clear_length) => {
		s.content.truncate(*clear_length);
		s.padding = Padding::None;
	    }
	}
	return s;
    }
}


#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys_test, FheAsciiChar};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{compare_result, test_fhe_string_string_pattern, test_fhe_add_char_pattern};
    use lazy_static::lazy_static;
    use tfhe::integer::RadixClientKey;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    test_fhe_string_string_pattern!(replace, "abc", "b", "lul");
    // test_fhe_string_string_pattern!(add, "ab", "");
    // test_fhe_string_string_pattern!(add, "aezfb", "cdfzefzef");
    // test_fhe_string_string_pattern!(add, "", "cd");
    
    // test_fhe_string_char_pattern!(add, "", 'a');
    // test_fhe_string_char_pattern!(add, "ab", 'a');
    // test_fhe_string_char_pattern!(add, "aezfb", 'a');
}

