mod accessors;
mod add;
mod change_case;
mod comparisons;
mod contains;
mod find;
mod is_empty;
mod repeat;
mod rsplit;
mod rsplitn;
pub mod split;
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
