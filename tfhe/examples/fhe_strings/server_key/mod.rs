mod change_case;

use tfhe::integer::ServerKey;

pub struct StringServerKey {
    pub integer_key: ServerKey,
}

impl From<ServerKey> for StringServerKey {
    fn from(integer_key: ServerKey) -> Self {
        Self { integer_key }
    }
}
