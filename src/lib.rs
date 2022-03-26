#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]

//! Micro-crate providing [`Write`]r and [`Read`]er implementations that apply
//! a stream cipher to an asynchronous or synchronous stream. This is useful for
//! ensuring that input or outputs go through an encryption or decryption layer,
//! such as if you're reading or writing to an encrypted cache file.
//!
//! Implementation is tied to the [Rust Crypto] ecosystem, allowing for any
//! stream cipher implementation that implements the relevant traits provided by
//! [`cipher`].
//!
//! Additionally, [`Reader`] and [`Writer`] implement [`AsyncRead`] and
//! [`AsyncWrite`] if their underlying reader and writer implement the
//! respective traits and the `tokio` feature is enabled. As a result, this also
//! allows for streaming reads via [`tokio_util`]'s [`ReaderStream`].
//!
//! [`Write`]: std::io::Write
//! [`Read`]: std::io::Read
//! [RustCrypto]: https://github.com/RustCrypto
//! [`AsyncRead`]: tokio::io::AsyncRead
//! [`AsyncWrite`]: tokio::io::AsyncWrite
//! [`tokio_util`]: https://docs.rs/tokio-util/latest/tokio_util/index.html
//! [`ReaderStream`]: https://docs.rs/tokio-util/latest/tokio_util/io/struct.ReaderStream.html
//!
//! ## ⚠️ Security Warning
//!
//! Stream ciphers do not ensure ciphertexts are authentic (i.e. by using a MAC
//! to verify ciphertext integrity), which can lead to serious vulnerabilities
//! if used incorrectly!
//!
//! This crate has not received any formal cryptographic and security reviews/audits.
//!
//! **USE AT YOUR OWN RISK!**

mod reader;
mod writer;

pub use reader::Reader;
pub use writer::Writer;

/// Convenience alias for a writer with a reasonable buffer.
pub type BufWriter<Inner, Cipher> = writer::Writer<Inner, Cipher, 4096>;
