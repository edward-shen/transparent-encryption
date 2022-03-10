use std::io::{Read, Result as IoResult};

use cipher::generic_array::GenericArray;
use cipher::{InnerIvInit, KeyInit, KeyIvInit, StreamCipher};

#[cfg(feature = "tokio")]
use core::marker::Unpin;
#[cfg(feature = "tokio")]
use core::pin::Pin;
#[cfg(feature = "tokio")]
use core::task::{Context, Poll};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, ReadBuf};

/// Reader that transparently applies a stream cipher to an underlying
/// synchronous or asynchronous reader.
///
/// Users should take caution and ensure or acknowledge if their selected stream
/// cipher implementation can panic when applying its keystream to bytes. If the
/// stream cipher implementation panics, then the read operation will result in
/// a panic.
///
/// This implementation does not buffer any data. If you'd like to have buffered
/// reads, it's best to wrap this struct in a reader that implements
/// [`BufRead`], such as [`BufReader`].
///
/// [`BufRead`]: std::io::BufRead
/// [`BufReader`]: std::io::BufReader
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Reader<Inner, StreamCipher> {
    reader: Inner,
    cipher: StreamCipher,
}

impl<Inner, Cipher> Reader<Inner, Cipher> {
    /// Constructs a new reader that applies the provided stream cipher to the
    /// output of the inner reader.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Read;
    ///
    /// use chacha20::ChaCha20;
    /// use cipher::generic_array::GenericArray;
    /// use cipher::KeyIvInit;
    /// use transparent_encryption::Reader;
    ///
    /// let bytes = [0x73, 0x1a, 0x2b, 0xe6, 0x24, 0x7d, 0x51, 0x9b, 0xe9, 0x91, 0x38];
    /// let cipher = ChaCha20::new(&GenericArray::from([1; 32]), &GenericArray::from([1; 12]));
    /// let mut reader = Reader::new(&bytes[..], cipher);
    ///
    /// let mut output = vec![];
    /// reader.read_to_end(&mut output)?;
    ///
    /// assert_eq!(output, b"hello world");
    ///
    /// # std::io::Result::Ok(())
    /// ```
    pub const fn new(reader: Inner, cipher: Cipher) -> Self {
        Self { reader, cipher }
    }
}

impl<Inner, Cipher> Reader<Inner, Cipher>
where
    Cipher: KeyIvInit,
{
    /// Convenience constructor for ciphers that implement [`KeyIvInit`], such
    /// as the [`ChaCha20`] family of stream ciphers.
    ///
    /// Constructs a new reader that constructs and applies the provided stream
    /// cipher to the output of the inner reader.
    ///
    /// # Examples
    ///
    /// ```
    /// use chacha20::ChaCha20;
    /// use cipher::generic_array::GenericArray;
    /// use transparent_encryption::Reader;
    ///
    /// let bytes = b"some input data";
    /// let reader: Reader<_, ChaCha20> = Reader::new_from_parts(
    ///     &bytes,
    ///     &GenericArray::from([1; 32]),
    ///     &GenericArray::from([1; 12])
    /// );
    /// ```
    ///
    /// [`KeyIvInit`]: cipher::KeyIvInit
    /// [`ChaCha20`]: https://docs.rs/chacha20/
    pub fn new_from_parts(
        reader: Inner,
        key: &GenericArray<u8, Cipher::KeySize>,
        nonce: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(reader, Cipher::new(key, nonce))
    }
}

impl<Inner, Cipher> Reader<Inner, Cipher>
where
    Cipher: KeyInit,
{
    /// Convenience constructor for ciphers that implement [`KeyInit`], such as
    /// the [`Rabbit`] stream cipher.
    ///
    /// Constructs a new reader that constructs and applies the provided stream
    /// cipher to the output of the inner reader.
    ///
    /// [`KeyInit`]: cipher::KeyInit
    /// [`Rabbit`]: https://docs.rs/rabbit/
    pub fn new_from_key(reader: Inner, key: &GenericArray<u8, Cipher::KeySize>) -> Self {
        Self::new(reader, Cipher::new(key))
    }
}

impl<Inner, Cipher> Reader<Inner, Cipher>
where
    Cipher: InnerIvInit,
{
    /// Convenience constructor for ciphers that implement [`InnerIvInit`]. This
    /// generally shouldn't be implemented for stream ciphers.
    ///
    /// Constructs a new reader that constructs and applies the provided stream
    /// cipher to the output of the inner reader.
    ///
    /// [`InnerIvInit`]: cipher::InnerIvInit
    pub fn new_from_inner_iv(
        reader: Inner,
        inner: Cipher::Inner,
        iv: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(reader, Cipher::inner_iv_init(inner, iv))
    }
}

impl<Inner, Cipher> Read for Reader<Inner, Cipher>
where
    Inner: Read,
    Cipher: StreamCipher,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let bytes_read = self.reader.read(buf)?;
        self.cipher.apply_keystream(&mut buf[..bytes_read]);
        Ok(bytes_read)
    }
}

#[cfg(feature = "tokio")]
impl<Inner, Cipher> AsyncRead for Reader<Inner, Cipher>
where
    Inner: AsyncRead + Unpin,
    Cipher: StreamCipher + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<IoResult<()>> {
        let start_index = buf.filled().len();
        let me = self.get_mut();
        match Pin::new(&mut me.reader).poll_read(cx, buf) {
            res @ Poll::Ready(Ok(())) => {
                assert!(start_index <= buf.filled_mut().len());
                let buffer = &mut buf.filled_mut()[start_index..];
                Pin::new(&mut me.cipher).apply_keystream(buffer);
                res
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod test {
    use cipher::inout::InOutBuf;
    use cipher::{StreamCipher, StreamCipherError};

    pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    pub struct BadCipher;

    impl StreamCipher for BadCipher {
        fn try_apply_keystream_inout(
            &mut self,
            buf: InOutBuf<'_, '_, u8>,
        ) -> Result<(), StreamCipherError> {
            for c in buf.into_out() {
                *c ^= 0b10101010;
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod read {
    use std::io::Read;

    use super::test::{BadCipher, TestResult};
    use super::Reader;

    #[test]
    fn simple() -> TestResult<()> {
        let input = [0b10101010, 0b01010101];
        let mut reader = Reader::new(&input[..], BadCipher);
        let mut data = Vec::with_capacity(input.len());
        reader.read_to_end(&mut data)?;
        assert_eq!(data, &[0b00000000, 0b11111111]);
        Ok(())
    }

    #[test]
    fn read_empty() -> TestResult<()> {
        let input = [];
        let mut reader = Reader::new(&input[..], BadCipher);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        assert!(data.is_empty());
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tokio_async_read {
    use super::test::{BadCipher, TestResult};
    use super::Reader;

    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn read() -> TestResult<()> {
        let input = [0b10101010, 0b01010101];
        let mut reader = Reader::new(&input[..], BadCipher);
        let mut output_buffer = vec![];
        AsyncReadExt::read_buf(&mut reader, &mut output_buffer).await?;
        assert_eq!(output_buffer, &[0b00000000, 0b11111111]);
        Ok(())
    }

    #[tokio::test]
    async fn read_empty() -> TestResult<()> {
        let input = [];
        let mut reader = Reader::new(&input[..], BadCipher);
        let mut output_buffer = vec![];
        AsyncReadExt::read_buf(&mut reader, &mut output_buffer).await?;
        assert!(output_buffer.is_empty());
        Ok(())
    }
}
