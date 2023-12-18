## Bounty program
This repository is a clone of https://github.com/zama-ai/tfhe-rs used to work on the bounty program "
Create a string library that works on encrypted data using TFHE-rs". The code relevant to the bounty is in [/tfhe/examples/fhe_strings](https://github.com/M-Bln/tfhe-rs-string/tree/main/tfhe/examples/fhe_strings).

# A library to fully homomorphically perform standard operations on strings.

The type `FheAsciiChar` is a wrapper type for a `RadixCiphertext` encoding an integer of 8 bits (an ASCII character).
The type `FheString` is a wrapper type around its character content, a `Vec<FheAsciiChar>`. In order to obfuscate the length of the string,
its content can be padded by zeros characters `'\0'`. We allow those characters anywhere in the string, they are ignored after decryption.

## Command line executable to time functions.

We provide a command line executable to time functions and compare them with the one from the standard library.
For an example of a quick timing, for functions taking only one or two unpadded strings:

`cargo run --features="integer, seeder_unix" --example fhe_strings -- foo oo`

For a complete timing, including functions taking additional arguments and character patterns:

`cargo run --features="integer, seeder_unix" --example fhe_strings -- foo oo -c o -r bar -i 2 -p 1`

For an explanation of the different arguments and flags:

`cargo run --features="integer, seeder_unix" --example fhe_strings -- --help`

#Example of output
```
function:                           find
arguments:
  └ encrypted string                "foo"
    └ 1 padding zeros
  └  clear string                   "oo"
results:
  ├ std result:                     Some(1)
  └ FHE result:                     Some(1)
time:                               78.578501ms
```


## Example

```
let (client_key, server_key) = gen_keys_test();
let encrypted_str1 = client_key.encrypt_str("ab").unwrap();
let encrypted_str2 = client_key.encrypt_str("bc").unwrap();
let add_str1_str2 = server_key.add_encrypted(encrypted_str1, &encrypted_str2);
let decrypted_str = client_key.decrypt_string(&add_str1_str2).unwrap();
assert_eq!(decrypted_str, "abbc");
```

## Padding and performence

Allowing padding zeros anywhere in the string permits to have good performence on some functions. For instance
it allows to concatenate string just by concatenation of their `content`s (vectors of `FheAsciiChar` eventually with padding).
Pushing the padding back to the end of the string is costly, the complexity is O(s.content.len()^2) FHE operations.
Some functions such as `find` in `s` with a character pattern works well even if the string has padding anywhere and its complexity
is O(s.content.len()) FHE operations. Some functions such as `split` with an encrypted string pattern require the padding of s to be final.
We chose to push back the padding zeros only when it is necessary for the algorithm to work. For this purpose the function
requiring the padding to be final call `push_padding_to_end` when necessary.