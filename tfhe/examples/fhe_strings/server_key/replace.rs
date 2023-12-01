use crate::ciphertext::{ClearOrEncrypted, FheAsciiChar, FheStrLength, FheString, Padding};
use crate::server_key::StringServerKey;

impl StringServerKey {
    pub fn replace_encrypted(&self, s: &FheString, pattern: &FheString) -> FheString {
	let splited_s = self.split_encrypted(s, pattern);
	let mut result = FheString {
	    content: Vec::new(),
	    length: ClearOrEncrypted::Clear(0),
	    padding: Padding::None,
	}
	for part in s.parts {
	    result = self.add_encrypted(result, part);
	}
    }
}
