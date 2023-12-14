mod accessors;
mod add;
mod change_case;
mod comparisons;
mod contains;
mod find;
pub mod is_empty;
mod length_arithmetic;
mod repeat;
mod replace;
mod rsplit;
mod rsplitn;
pub mod split;
mod split_ascii_whitespace;
mod split_inclusive;
mod split_terminator;
mod starts_with;
mod strip;
mod substring;
mod trim;

use tfhe::integer::ServerKey;

pub struct StringServerKey {
    pub integer_key: ServerKey,
}

impl From<ServerKey> for StringServerKey {
    fn from(integer_key: ServerKey) -> Self {
        Self { integer_key }
    }
}
