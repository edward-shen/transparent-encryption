# `transparent-encryption`

_Name TDB_

Micro-crate providing reader and writer wrappers that transparently encrypt and
decrypt data with stream ciphers.

## ⚠️ Security Warning

Stream ciphers do not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities if used
incorrectly!

This crate has not received any formal cryptographic and security reviews/audits.

**USE AT YOUR OWN RISK!**

## Minimum Supported Rust Version

This crate does _not_ consider changing MSRV a breaking change. This crate
officially supports the latest Rust version only. We provide `rust-version`
metadata to `Cargo.toml` as a sanity check for users.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
