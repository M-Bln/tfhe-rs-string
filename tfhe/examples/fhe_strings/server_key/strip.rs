use crate::ciphertext::{FheAsciiChar, ClearOrEncrypted, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

impl StringServerKey {
    pub fn strip_encrypted_prefix(
	&self,
	s: &FheString,
	prefix: &FheString,
    ) -> (RadixCiphertext, FheString) {
	let zero = self.create_zero();
	match (&s.length, &prefix.length) {
            (&FheStrLength::Clear(l), &FheStrLength::Clear(l_prefix)) if l_prefix > l => return (zero, s.clone()),
            (_, &FheStrLength::Clear(l_prefix)) if l_prefix > s.content.len() => return (zero, s.clone()),
            _ => (),
        }
	match (s.padding, prefix.padding) {
            (Padding::None | Padding::Final, Padding::None | Padding::Final) => {
                self.strip_encrypted_prefix_no_init_padding(s, prefix)
            }
            (Padding::None | Padding::Final, _) => {
                self.strip_encrypted_prefix_no_init_padding(s, &self.remove_initial_padding(prefix))
            }
            (_, Padding::None | Padding::Final) => {
                self.strip_encrypted_prefix_no_init_padding(&self.remove_initial_padding(s), prefix)
            }
            _ => self.strip_encrypted_prefix_no_init_padding(
                &self.remove_initial_padding(s),
                &self.remove_initial_padding(prefix),
            ),
        }
    }

    pub fn strip_encrypted_prefix_no_init_padding(
	&self,
	s: &FheString,
	prefix: &FheString,
    ) -> (RadixCiphertext, FheString) {
	let starts_with_prefix = self.starts_with_encrypted_no_init_padding(s, prefix);
	(
	    starts_with_prefix,   
	    FheString {
		content : match prefix.length {
		    ClearOrEncrypted::Clear(prefix_length) => self.strip_clear_length_encrypted_prefix_content(&s.content, &prefix.content, &starts_with_prefix, prefix_length as u8),
		    ClearOrEncrypted::Encrypted(prefix_length) => self.strip_encrypted_length_encrypted_prefix_content(&s.content, &prefix.content, &starts_with_prefix, &prefix_length),
	    },
		length : self.new_length(&s.length, &prefix.length, &starts_with_prefix),
		padding : match s.padding {
		    Padding::None => Padding::Initial,
		    _ => Padding::InitialAndFinal,
		} 
	    }
	)
	// match prefix.length {
	//     ClearOrEncrypted::Clear(prefix_length) => (
	// 	starts_with_prefix,
	// 	FheString {
	// 	    content : vec![FheAsciiChar(self.create_zero()); prefix_length].extend_from_slice(&s.content[prefix_length..]),
	// 	    length : match s.length {
	// 		ClearOrEncrypted::Clear(s_length) => ClearOrEncrypted::Clear(s_length - prefix_length),
	// 		ClearOrEncrypted::Encrypted(s_length) => ClearOrEncrypted::Encrypted(self.integer_key.scalar_sub_parallelized(&s_length, prefix_length)),
	// 	    },
	// 	    padding : match s.padding {
	// 		Padding::None if prefix_length == 0 => Padding::None,
	// 		Padding::None | Padding::Initial  => Padding::Initial,
	// 		_ => Padding::InitialAndFinal,
	// 	    }, 
	// 	}
	//     ),
	//     ClearOrEncrypted::Encrypted(prefix_length) => ()
	// }
    }



    fn new_length(&self, string_length: &FheStrLength, prefix_length: &FheStrLength, starts_with_prefix: &RadixCiphertext) -> FheStrLength {
	match (string_length, prefix_length) {
	    (ClearOrEncrypted::Clear(str_length), ClearOrEncrypted::Clear(pfx_length)) => ClearOrEncrypted::Encrypted(
		self.integer_key.unchecked_cmux(
		    &starts_with_prefix,
		    &self.create_n(*str_length as u8 - *pfx_length as u8),
		    &self.create_n(*str_length as u8),
		)
	    ),
	    (ClearOrEncrypted::Encrypted(str_length), ClearOrEncrypted::Clear(pfx_length)) => ClearOrEncrypted::Encrypted(
		self.integer_key.unchecked_cmux(
		    &starts_with_prefix,
		    &self.integer_key.scalar_sub_parallelized(str_length, *pfx_length as u8),
		    &str_length,
		)
	    ),
	    (ClearOrEncrypted::Clear(str_length), ClearOrEncrypted::Encrypted(pfx_length)) => ClearOrEncrypted::Encrypted(
		self.integer_key.unchecked_cmux(
		    &starts_with_prefix,
		    &self.integer_key.scalar_add_parallelized(
			&self.integer_key.neg_parallelized(pfx_length),
			*str_length as u8
		    ),
		    &self.create_n(*str_length as u8),
		)
	    ),
	    (ClearOrEncrypted::Encrypted(str_length), ClearOrEncrypted::Encrypted(pfx_length)) => ClearOrEncrypted::Encrypted(
		self.integer_key.unchecked_cmux(
		    &starts_with_prefix,
		    &self.integer_key.sub_parallelized(str_length, pfx_length),
		    &str_length,
		)
	    ),
	}
    }

    fn strip_clear_length_encrypted_prefix_content (&self, content: &[FheAsciiChar], prefix_content: &[FheAsciiChar], starts_with_prefix: &RadixCiphertext, prefix_length: u8) -> Vec<FheAsciiChar> {
	let result: Vec<FheAsciiChar> = Vec::with_capacity(content.len());
	for n in 0..prefix_length {
	    result.push(self.integer_key.unchecked_cmux(&starts_with_prefix, &prefix_content[n as usize], &content[n as usize]));
	}
	result.extend_from_slice(content[prefix_length..]);
	result
    }

    fn strip_encrypted_length_encrypted_prefix_content (&self, content: &[FheAsciiChar], prefix_content: &[FheAsciiChar], starts_with_prefix: &RadixCiphertext, prefix_length: &RadixCiphertext) -> Vec<FheAsciiChar>{
	let result: Vec<FheAsciiChar> = Vec::with_capacity(content.len());
	let overlapping_content_length = std::cmp::min(content.len(), prefix_content.len()); 
	for n in 0..overlapping_content_length {
	    let from_prefix = self.integer_key.bitand_parallelized(
		&starts_with_prefix,
		&self.intger_key.scalar_ge_parallelized(prefix_length, n+1),
	    );
	    result.push(self.integer_key.unchecked_cmux(&from_prefix, &prefix_content[n], &content[n]));
	}
	result.extend_from_slice(content[overlapping_content_length..]);
	result
    }
}
