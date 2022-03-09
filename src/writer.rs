use std::io::{Result as IoResult, Write};

use cipher::generic_array::GenericArray;
use cipher::{InnerIvInit, KeyInit, KeyIvInit, StreamCipher};

#[cfg(feature = "tokio")]
use core::marker::Unpin;
#[cfg(feature = "tokio")]
use core::pin::Pin;
#[cfg(feature = "tokio")]
use core::task::{Context, Poll};
#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;

pub struct EncryptedWriter<Writer, StreamCipher, const BUFFER_SIZE: usize> {
    writer: Writer,
    cipher: StreamCipher,
    buffer: [u8; BUFFER_SIZE],
    buffer_end: usize,
}

impl<Writer, Cipher, const BUFFER_SIZE: usize> EncryptedWriter<Writer, Cipher, BUFFER_SIZE>
where
    Cipher: StreamCipher,
{
    fn push_to_buffer(&mut self, bytes_written: usize, buf: &[u8]) -> usize {
        self.take_bytes(bytes_written);
        self.push_bytes(buf)
    }

    /// Move the remaining to the beginning of the buffer, and updates the tail
    /// index.
    fn take_bytes(&mut self, bytes_written: usize) {
        assert!(bytes_written <= self.buffer_end);
        self.buffer_end -= bytes_written;
        for i in 0..self.buffer_end {
            self.buffer[i] = self.buffer[bytes_written + i];
        }
    }

    fn push_bytes(&mut self, buf: &[u8]) -> usize {
        let to_write = buf.len().min(BUFFER_SIZE - self.buffer_end);
        for (i, byte) in buf.iter().enumerate().take(to_write) {
            self.buffer[self.buffer_end + i] = *byte;
        }
        self.encrypt_bytes(to_write);
        to_write
    }

    fn encrypt_bytes(&mut self, num_bytes: usize) {
        self.cipher
            .apply_keystream(&mut self.buffer[self.buffer_end..self.buffer_end + num_bytes]);
        self.buffer_end += num_bytes;
    }
}

impl<Writer, Cipher, const BUFFER_SIZE: usize> EncryptedWriter<Writer, Cipher, BUFFER_SIZE> {
    pub fn new(writer: Writer, cipher: Cipher) -> Self {
        Self {
            writer,
            cipher,
            buffer: [0; BUFFER_SIZE],
            buffer_end: 0,
        }
    }
}

impl<Writer, Cipher, const BUFFER_SIZE: usize> EncryptedWriter<Writer, Cipher, BUFFER_SIZE>
where
    Cipher: KeyIvInit,
{
    pub fn new_from_parts(
        writer: Writer,
        key: &GenericArray<u8, Cipher::KeySize>,
        nonce: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(writer, Cipher::new(key, nonce))
    }
}

impl<Writer, Cipher, const BUFFER_SIZE: usize> EncryptedWriter<Writer, Cipher, BUFFER_SIZE>
where
    Cipher: KeyInit,
{
    pub fn new_from_key(writer: Writer, key: &GenericArray<u8, Cipher::KeySize>) -> Self {
        Self::new(writer, Cipher::new(key))
    }
}

impl<Writer, Cipher, const BUFFER_SIZE: usize> EncryptedWriter<Writer, Cipher, BUFFER_SIZE>
where
    Cipher: InnerIvInit,
{
    pub fn new_from_inner_iv(
        writer: Writer,
        inner: Cipher::Inner,
        iv: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(writer, Cipher::inner_iv_init(inner, iv))
    }
}

impl<Writer, Cipher, const BUFFER_SIZE: usize> Write
    for EncryptedWriter<Writer, Cipher, BUFFER_SIZE>
where
    Writer: Write,
    Cipher: StreamCipher,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // Try to write our buffer first.
        let bytes_written = self.writer.write(&self.buffer[..self.buffer_end])?;
        Ok(self.push_to_buffer(bytes_written, buf))
    }

    fn flush(&mut self) -> IoResult<()> {
        let mut bytes_written = 0;
        while bytes_written < self.buffer_end {
            bytes_written += self
                .writer
                .write(&self.buffer[bytes_written..self.buffer_end])?;
        }

        self.writer.flush()
    }
}

#[cfg(feature = "tokio")]
impl<Writer, Cipher, const BUFFER_SIZE: usize> AsyncWrite
    for EncryptedWriter<Writer, Cipher, BUFFER_SIZE>
where
    Writer: AsyncWrite + Unpin,
    Cipher: StreamCipher + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<IoResult<usize>> {
        let me = self.get_mut();

        match Pin::new(&mut me.writer).poll_write(cx, &me.buffer[..me.buffer_end]) {
            Poll::Ready(Ok(bytes)) => {
                // We don't really care how many bytes we've written to the
                // underlying writer, just how many we've written to our buffer
                Poll::Ready(Ok(me.push_to_buffer(bytes, buf)))
            }
            Poll::Pending => {
                // Underlying writer is full, lets try to add to our buffer instead
                match me.push_bytes(buf) {
                    // Buffer is full as well, bubble up pending status
                    0 => Poll::Pending,
                    // Written n bytes to the buffer
                    n => Poll::Ready(Ok(n)),
                }
            }
            e @ Poll::Ready(Err(_)) => e,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        let me = self.get_mut();
        loop {
            match Pin::new(&mut me.writer).poll_write(cx, &me.buffer[..me.buffer_end]) {
                Poll::Ready(Ok(bytes)) => {
                    if me.buffer_end == 0 {
                        // Fully flushed, return
                        break Poll::Ready(Ok(()));
                    }

                    // move the buffer forward
                    me.take_bytes(bytes);
                }
                Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
                Poll::Pending => break Poll::Pending,
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        if self.buffer_end == 0 {
            return self.poll_shutdown(cx);
        }
        let mut me = self.get_mut();
        match Pin::new(&mut me).poll_flush(cx) {
            Poll::Ready(Ok(_)) => Pin::new(&mut me.writer).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Result as IoResult, Write};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use cipher::inout::InOutBuf;
    use cipher::{StreamCipher, StreamCipherError};
    use tokio::io::AsyncWrite;

    pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    pub struct ThreeByteWriter(pub Vec<u8>);

    impl Write for ThreeByteWriter {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            if buf.len() >= 3 {
                self.0.extend_from_slice(&buf[..3]);
                Ok(3)
            } else {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl AsyncWrite for ThreeByteWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            Poll::Ready(self.write(buf))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context) -> Poll<IoResult<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context) -> Poll<IoResult<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    pub struct IncrementalCipher(u8);

    impl StreamCipher for IncrementalCipher {
        fn try_apply_keystream_inout(
            &mut self,
            buf: InOutBuf<'_, '_, u8>,
        ) -> Result<(), StreamCipherError> {
            for c in buf.into_out() {
                *c ^= self.0;
                self.0 = self.0.wrapping_add(1);
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod write {
    use std::io::Write;

    use super::test::*;
    use super::EncryptedWriter;

    #[test]
    fn simple_large_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer =
            EncryptedWriter::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        writer.write_all(&data)?;
        writer.flush()?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[test]
    fn simple_small_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer =
            EncryptedWriter::<_, _, 64>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        writer.write_all(&data)?;
        writer.flush()?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[test]
    fn slow_writer() -> TestResult<()> {
        let mut underlying = ThreeByteWriter(vec![]);
        let mut writer =
            EncryptedWriter::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        writer.write_all(&data)?;
        writer.flush()?;
        assert_eq!(underlying.0, [0].repeat(data.len()));
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tokio_async_write {
    use super::test::*;
    use super::EncryptedWriter;

    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn simple_large_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer =
            EncryptedWriter::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        AsyncWriteExt::write_all(&mut writer, &data).await?;
        writer.flush().await?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[tokio::test]
    async fn simple_small_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer =
            EncryptedWriter::<_, _, 64>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        AsyncWriteExt::write_all(&mut writer, &data).await?;
        writer.flush().await?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[tokio::test]
    async fn slow_writer() -> TestResult<()> {
        let mut underlying = ThreeByteWriter(vec![]);
        let mut writer =
            EncryptedWriter::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        AsyncWriteExt::write_all(&mut writer, &data).await?;
        writer.flush().await?;
        assert_eq!(underlying.0, [0].repeat(data.len()));
        Ok(())
    }
}
