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

/// Writer that transparently applies a stream cipher to an underlying
/// synchronous or asynchronous writer.
///
/// Users should take caution and ensure or acknowledge if their selected stream
/// cipher implementation can panic when applying its keystream to bytes. If the
/// stream cipher implementation panics, then the write operation will result in
/// a panic.
///
/// [`Writer`] must maintain an internal stack-allocated buffer to store
/// already-encrypted data. The size is dependent on the user provided
/// `BUFFER_SIZE`. Reasonable defaults will depend on your use case, but
/// values such as `4096` or `8192` are pretty good starting points.
///
/// `BUFFER_SIZE` cannot be zero. This is a restriction of the [`Write`] trait,
/// as it only provides an immutable reference to the buffer of data to be
/// written. As a result, we need a buffer to modify and encrypt the data before
/// providing the encrypted bytes to the underlying writer.
///
/// Like all buffered [`Write`] implementors, it is not guaranteed that written
/// bytes will be immediately available for reading. If this is needed, you
/// should call [`Writer::flush`] before attempting any read calls.
///
/// However, unlike other buffered [`Write`] implementors, this makes no attempt
/// to coalesce multiple smaller write calls into one larger one. As a result,
/// if buffered writing is preferred, it is recommended to wrap the underlying
/// writer in a [`BufWriter`].
///
/// [`Write`]: std::io::Write
/// [`BufWriter`]: std::io::BufWriter
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Writer<Inner, StreamCipher, const BUFFER_SIZE: usize> {
    writer: Inner,
    cipher: StreamCipher,
    buffer: [u8; BUFFER_SIZE],
    buffer_end: usize,
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Default for Writer<Inner, Cipher, BUFFER_SIZE>
where
    Inner: Default,
    Cipher: Default,
{
    fn default() -> Self {
        Self {
            writer: Inner::default(),
            cipher: Cipher::default(),
            buffer: [0; BUFFER_SIZE],
            buffer_end: 0,
        }
    }
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Writer<Inner, Cipher, BUFFER_SIZE>
where
    Cipher: StreamCipher,
{
    /// Removes the number of bytes written from the internal buffer, and
    /// inserts and encrypts as much as possible from the provided buffer.
    fn update_buffer(&mut self, bytes_written: usize, buf: &[u8]) -> usize {
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

    /// Appends the provided bytes, encrypting the ones that we could fit into
    /// the internal buffer, and returning the number of bytes written to our
    /// buffer.
    fn push_bytes(&mut self, buf: &[u8]) -> usize {
        let to_write = buf.len().min(BUFFER_SIZE - self.buffer_end);
        for (i, byte) in buf.iter().enumerate().take(to_write) {
            self.buffer[self.buffer_end + i] = *byte;
        }

        self.cipher
            .apply_keystream(&mut self.buffer[self.buffer_end..self.buffer_end + to_write]);
        self.buffer_end += to_write;
        to_write
    }
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Writer<Inner, Cipher, BUFFER_SIZE> {
    /// Constructs a new writer that applies the provided stream cipher to the
    /// the provided input, before writing the encrypted data to the inner
    /// writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Write;
    ///
    /// use chacha20::ChaCha20;
    /// use cipher::generic_array::GenericArray;
    /// use cipher::KeyIvInit;
    /// use transparent_encryption::Writer;
    ///
    /// let mut file = vec![];
    /// let cipher = ChaCha20::new(&GenericArray::from([1; 32]), &GenericArray::from([1; 12]));
    /// let mut writer: Writer<_, _, 4096> = Writer::new(&mut file, cipher);
    ///
    /// writer.write_all(b"hello world")?;
    /// writer.flush()?;
    ///
    /// assert_eq!(file, [0x73, 0x1a, 0x2b, 0xe6, 0x24, 0x7d, 0x51, 0x9b, 0xe9, 0x91, 0x38]);
    ///
    /// # std::io::Result::Ok(())
    /// ```
    ///
    /// # Panics
    ///
    /// This will panic if `BUFFER_SIZE` is zero.
    pub const fn new(writer: Inner, cipher: Cipher) -> Self {
        assert!(BUFFER_SIZE > 0, "BUFFER_SIZE cannot be zero!");
        Self {
            writer,
            cipher,
            buffer: [0; BUFFER_SIZE],
            buffer_end: 0,
        }
    }
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Writer<Inner, Cipher, BUFFER_SIZE>
where
    Cipher: KeyIvInit,
{
    /// Convenience constructor for ciphers that implement [`KeyIvInit`], such
    /// as the [`ChaCha20`] family of stream ciphers.
    ///
    /// Constructs a new writer that applies the provided stream cipher to the
    /// the provided input, before writing the encrypted data to the inner
    /// writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use chacha20::ChaCha20;
    /// use cipher::generic_array::GenericArray;
    /// use transparent_encryption::Writer;
    ///
    /// let mut file = vec![];
    /// let writer: Writer<_, _, 4096> = Writer::new_from_parts(
    ///     &mut file,
    ///     &GenericArray::from([1; 32]),
    ///     &GenericArray::from([1; 12]),
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// This will panic if `BUFFER_SIZE` is zero.
    ///
    /// [`KeyIvInit`]: cipher::KeyIvInit
    /// [`ChaCha20`]: https://docs.rs/chacha20/
    pub fn new_from_parts(
        writer: Inner,
        key: &GenericArray<u8, Cipher::KeySize>,
        nonce: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(writer, Cipher::new(key, nonce))
    }
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Writer<Inner, Cipher, BUFFER_SIZE>
where
    Cipher: KeyInit,
{
    /// Convenience constructor for ciphers that implement [`KeyInit`], such as
    /// the [`Rabbit`] stream cipher.
    ///
    /// Constructs a new writer that constructs and applies the provided stream
    /// cipher to the output of the inner writer.
    ///
    /// # Panics
    ///
    /// This will panic if `BUFFER_SIZE` is zero.
    ///
    /// [`KeyInit`]: cipher::KeyInit
    /// [`Rabbit`]: https://docs.rs/rabbit/
    pub fn new_from_key(writer: Inner, key: &GenericArray<u8, Cipher::KeySize>) -> Self {
        Self::new(writer, Cipher::new(key))
    }
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Writer<Inner, Cipher, BUFFER_SIZE>
where
    Cipher: InnerIvInit,
{
    /// Convenience constructor for ciphers that implement [`InnerIvInit`]. This
    /// generally shouldn't be implemented for stream ciphers.
    ///
    /// Constructs a new writer that constructs and applies the provided stream
    /// cipher to the output of the inner writer.
    ///
    /// # Panics
    ///
    /// This will panic if `BUFFER_SIZE` is zero.
    ///
    /// [`InnerIvInit`]: cipher::InnerIvInit
    pub fn new_from_inner_iv(
        writer: Inner,
        inner: Cipher::Inner,
        iv: &GenericArray<u8, Cipher::IvSize>,
    ) -> Self {
        Self::new(writer, Cipher::inner_iv_init(inner, iv))
    }
}

impl<Inner, Cipher, const BUFFER_SIZE: usize> Write for Writer<Inner, Cipher, BUFFER_SIZE>
where
    Inner: Write,
    Cipher: StreamCipher,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // Try to write our buffer first.
        let bytes_written = self.writer.write(&self.buffer[..self.buffer_end])?;
        Ok(self.update_buffer(bytes_written, buf))
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
impl<Inner, Cipher, const BUFFER_SIZE: usize> AsyncWrite for Writer<Inner, Cipher, BUFFER_SIZE>
where
    Inner: AsyncWrite + Unpin,
    Cipher: StreamCipher + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<IoResult<usize>> {
        let me = self.get_mut();

        match Pin::new(&mut me.writer).poll_write(cx, &me.buffer[..me.buffer_end]) {
            Poll::Ready(Ok(bytes)) => {
                // We don't really care how many bytes we've written to the
                // underlying writer, just how many we've written to our buffer
                Poll::Ready(Ok(me.update_buffer(bytes, buf)))
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
    use super::Writer;

    #[test]
    fn simple_large_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer = Writer::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        writer.write_all(&data)?;
        writer.flush()?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[test]
    fn simple_small_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer = Writer::<_, _, 64>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        writer.write_all(&data)?;
        writer.flush()?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[test]
    fn slow_writer() -> TestResult<()> {
        let mut underlying = ThreeByteWriter(vec![]);
        let mut writer = Writer::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
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
    use super::Writer;

    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn simple_large_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer = Writer::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        AsyncWriteExt::write_all(&mut writer, &data).await?;
        writer.flush().await?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[tokio::test]
    async fn simple_small_buffer() -> TestResult<()> {
        let mut underlying = vec![];
        let mut writer = Writer::<_, _, 64>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        AsyncWriteExt::write_all(&mut writer, &data).await?;
        writer.flush().await?;
        assert_eq!(underlying, [0].repeat(data.len()));
        Ok(())
    }

    #[tokio::test]
    async fn slow_writer() -> TestResult<()> {
        let mut underlying = ThreeByteWriter(vec![]);
        let mut writer = Writer::<_, _, 2048>::new(&mut underlying, IncrementalCipher::default());
        let data: Vec<u8> = (0..100).collect();
        AsyncWriteExt::write_all(&mut writer, &data).await?;
        writer.flush().await?;
        assert_eq!(underlying.0, [0].repeat(data.len()));
        Ok(())
    }
}
