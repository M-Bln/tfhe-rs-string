//use tfhe::{IntegerClientKey};
//use tfhe::prelude::*;
use tfhe::high_level_api::integers::IntegerClientKey;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct StingClientKey {
    pub key: Option<IntegerClientKey>,
}

impl From<IntegerClientKey> for StringClientKey {
    fn from(integer_client_key: IntegerClientKey) -> Self {
	Self {
	    key,
	}
    }
}
