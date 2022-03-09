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

pub struct EncryptedReader<Reader, StreamCipher> {
    reader: Reader,
    cipher: StreamCipher,
}

impl<Reader, Cipher> EncryptedReader<Reader, Cipher> {
    pub fn new(reader: Reader, cipher: Cipher) -> Self {
        Self { reader, cipher }
    }
}

impl<Reader, Cipher> EncryptedReader<Reader, Cipher>
where
    Cipher: KeyIvInit,
{
    pub fn new_from_parts(
        reader: Reader,
        key: &GenericArray<u8, Cipher::KeySize>,
        nonce: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(reader, Cipher::new(key, nonce))
    }
}

impl<Reader, Cipher> EncryptedReader<Reader, Cipher>
where
    Cipher: KeyInit,
{
    pub fn new_from_key(reader: Reader, key: &GenericArray<u8, Cipher::KeySize>) -> Self {
        Self::new(reader, Cipher::new(key))
    }
}

impl<Reader, Cipher> EncryptedReader<Reader, Cipher>
where
    Cipher: InnerIvInit,
{
    pub fn new_from_inner_iv(
        reader: Reader,
        inner: Cipher::Inner,
        iv: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(reader, Cipher::inner_iv_init(inner, iv))
    }
}

impl<Reader, Cipher> Read for EncryptedReader<Reader, Cipher>
where
    Reader: Read,
    Cipher: StreamCipher,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let bytes_read = self.reader.read(buf)?;
        self.cipher.apply_keystream(&mut buf[..bytes_read]);
        Ok(bytes_read)
    }
}

#[cfg(feature = "tokio")]
impl<Reader, Cipher> AsyncRead for EncryptedReader<Reader, Cipher>
where
    Reader: AsyncRead + Unpin,
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
    use super::EncryptedReader;

    #[test]
    fn simple() -> TestResult<()> {
        let input = [0b10101010, 0b01010101];
        let mut reader = EncryptedReader::new(&input[..], BadCipher);
        let mut data = Vec::with_capacity(input.len());
        reader.read_to_end(&mut data)?;
        assert_eq!(data, &[0b00000000, 0b11111111]);
        Ok(())
    }

    #[test]
    fn read_empty() -> TestResult<()> {
        let input = [];
        let mut reader = EncryptedReader::new(&input[..], BadCipher);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        assert!(data.is_empty());
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tokio_async_read {
    use super::test::{BadCipher, TestResult};
    use super::EncryptedReader;

    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn read() -> TestResult<()> {
        let input = [0b10101010, 0b01010101];
        let mut reader = EncryptedReader::new(&input[..], BadCipher);
        let mut output_buffer = vec![];
        AsyncReadExt::read_buf(&mut reader, &mut output_buffer).await?;
        assert_eq!(output_buffer, &[0b00000000, 0b11111111]);
        Ok(())
    }

    #[tokio::test]
    async fn read_empty() -> TestResult<()> {
        let input = [];
        let mut reader = EncryptedReader::new(&input[..], BadCipher);
        let mut output_buffer = vec![];
        AsyncReadExt::read_buf(&mut reader, &mut output_buffer).await?;
        assert!(output_buffer.is_empty());
        Ok(())
    }
}
