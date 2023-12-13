use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::client_key::ConversionError;
use crate::integer_arg::FheIntegerArg;
use crate::pattern::{FheCharPattern, FhePattern};
use crate::server_key::StringServerKey;
use tfhe::integer::RadixCiphertext;

pub type ResultFheString = (RadixCiphertext, FheString);

pub struct FheSplit {
    pub parts: Vec<FheString>,
    pub number_parts: RadixCiphertext,
    pub current_index: usize,
}

impl StringServerKey {
    pub fn is_ascii_white_space(&self, c: &FheAsciiChar) -> RadixCiphertext {
	let is_tab_feed_return = self.integer_key.bitand_parallelized(
	    &self.integer_key.scalar_ge_parallelized(&c.0, 9),
	    &self.integer_key.scalar_le_parallelized(&c.0, 13),
	);
	let is_space = self.integer_key.scalar_eq_parallelized(&c.0, 32);
	self.integer_key.bitor_parallelized(
	    &is_tab_feed_return,
	    &is_space,
	)
    }

    pub fn is_not_ascii_white_space(&self, c: &FheAsciiChar) -> RadixCiphertext {
	let is_not_tab_feed_return = self.integer_key.bitor_parallelized(
	    &self.integer_key.scalar_lt_parallelized(&c.0, 9),
	    &self.integer_key.scalar_gt_parallelized(&c.0, 13),
	);
	let is_not_space = self.integer_key.scalar_ne_parallelized(&c.0, 32);
	self.integer_key.bitand_parallelized(
	    &is_not_tab_feed_return,
	    &is_not_space,
	)
    }

    pub fn next_non_white_chunk(&self, s: &FheString, from: &RadixCiphertext) -> (RadixCiphertext, RadixCiphertext) {
	let result_content : Vec<FheAsciiChar>= Vec::with_capacity(s.content.len());
	let mut start_chunk = self.create_zero();
	let mut end_chunk = self.create_zero();
	let mut prev_is_not_content_in_range = self.create_true();
	let mut prev_non_white_and_in_range = self.create_zero();
	for (i, c) in s.content.iter().enumerate() {
	    let in_range = self.integer_key.scalar_le_parallelized(from, i as u32);
	    let non_white = self.is_not_ascii_white_space(c);
	    let non_white_and_in_range = self.integer_key.bitand_parallelized(&non_white, &in_range);
	    let is_content_in_range = self.integer_key.bitand_parallelized(&non_white_and_in_range, &self.integer_key.scalar_ne_parallelized(&c.0,0));

	    let first_content_in_range = self.integer_key.bitand_parallelized(
		&is_content_in_range,
		&prev_is_not_content_in_range,
	    );

	    let end_non_white_in_range = self.integer_key.bitand_parallelized(
		&prev_non_white_and_in_range,
		&self.integer_key.scalar_ne_parallelized(&non_white,1),
	    );

	    prev_is_not_content_in_range = self.integer_key.scalar_ne_parallelized(&is_content_in_range, 1);
	    prev_non_white_and_in_range = non_white_and_in_range;

	    start_chunk = self.integer_key.cmux_parallelized(
		&self.integer_key.bitand_parallelized(
		    &first_content_in_range,
		    &self.integer_key.scalar_eq_parallelized(&start_chunk,0),
		),
		&self.create_n(i as u8),
		&start_chunk,
	    );

	    end_chunk = self.integer_key.cmux_parallelized(
		&self.integer_key.bitand_parallelized(
		    &end_non_white_in_range,
		    &self.integer_key.scalar_eq_parallelized(&end_chunk,0),		    
		),
		&self.create_n(i as u8),
		&end_chunk,
	    );
	}
	end_chunk = self.integer_key.cmux_parallelized(
		&self.integer_key.bitand_parallelized(
		    &prev_non_white_and_in_range,
		    &self.integer_key.scalar_eq_parallelized(&end_chunk,0),
		),
		&self.create_n(s.content.len() as u8),
		&end_chunk,
	);
	// end_chunk = self.integer_key.cmux_parallelized(
	//     &end_chunk,
	//     &end_chunk,
	//     &self.integer_key.cmux_parallelized(
	// 	&prev_non_white_and_in_range,
	// 	&self.create_n(s.content.len() as u8),
	// 	&end_chunk,
	//     )
	// );
	(start_chunk, end_chunk)
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::{gen_keys, gen_keys_test, FheStrLength, Padding};
    use crate::client_key::StringClientKey;
    use crate::server_key::StringServerKey;
    use crate::{
        compare_result, test_fhe_split_char_pattern, test_fhe_split_string_pattern,
        test_splitn_char_pattern, test_splitn_string_pattern,
    };
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref KEYS: (StringClientKey, StringServerKey) = gen_keys_test();
        pub static ref CLIENT_KEY: &'static StringClientKey = &KEYS.0;
        pub static ref SERVER_KEY: &'static StringServerKey = &KEYS.1;
    }

    #[test]
    fn test_next_chunk(){
	let encrypted_s = CLIENT_KEY.encrypt_str("b c d").unwrap();
	let (start_chunk, end_chunk) = SERVER_KEY.next_non_white_chunk(&encrypted_s, &SERVER_KEY.create_n(1));
	let clear_start = CLIENT_KEY.decrypt_u8(&start_chunk);
	let clear_end = CLIENT_KEY.decrypt_u8(&end_chunk);
	assert_eq!((clear_start,clear_end),(2,3));
    }
}
