# A library to fully homomorphically perform standard operation on string.

The type `FheAsciiChar` is a wrapper type for a `RadixCiphertext` encoding an integer of 8 bits (an ascii char).
The type `FheString` is a wrapper type around its content, a `Vec<FheAsciiChar>`. In order to obfuscate the length of the string,
its content can be padded by zeros characters `'\0'`. We allow those character anywhere in the string, they are ignored after decryption.

## Command line executable to time functions.

We provide a command line executable to time functions and compare them with the one from the standard library.
For an example of a quick timing of functions taking one or two unpadded strings:

`cargo run --features="integer, seeder_unix" --example fhe_strings -- foo oo`

For a complete timing, including functions taking additional arguments and character patterns:

`cargo run --features="integer, seeder_unix" --example fhe_strings -- foo oo -c o -r bar -i 2 -p 1`.

For an explanation of the differents arguments and flag:

`cargo run --features="integer, seeder_unix" --example fhe_strings -- --help`


### Example

```
let (client_key, server_key) = gen_keys_test();
let encrypted_str1 = client_key.encrypt_str_random_padding("ab", 0).unwrap();
let encrypted_str2 = client_key.encrypt_str_random_padding("bc", 0).unwrap();
let add_str1_str2 = server_key.add_encrypted(encrypted_str1, &encrypted_str2);
let decrypted_str = client_key.decrypt_string(&add_str1_str2).unwrap();
assert_eq!(decrypted_str, "abbc");
```

#### Padding and performence

Allowing padding zeros anywhere in the string permits to have good performence on some functions. For instance
it allows to concatenate string just by concatenation of their `content`s (vectors of `FheAsciiChar` eventually with padding).
Pushing the padding back to the end of the string is costly, the complexity is O(s.content.len()^2) FHE operations.
Some functions such as `find` in `s` with a character pattern works well even if the string has padding anywhere and its complexity
is O(s.content.len()). Some functions such as `split` with an encrypted string pattern require the padding of s to be final.
We chose to push back the padding zeros only when it is necessary for the algorithm to work. For this purpose the function
requiring the padding to be final call `push_padding_to_end` when necessary.