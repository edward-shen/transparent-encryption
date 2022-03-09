use std::io::{Result as IoResult, Write};

use cipher::generic_array::GenericArray;
use cipher::{InnerIvInit, KeyInit, KeyIvInit, StreamCipher};

pub struct EncryptedWriter<Writer, StreamCipher, const BUFFER_SIZE: usize> {
    writer: Writer,
    cipher: StreamCipher,
    buffer: [u8; BUFFER_SIZE],
    buffer_end: usize,
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

        assert!(bytes_written <= self.buffer_end);

        // Move the remaining to the beginning of the buffer.
        for i in 0..self.buffer_end {
            self.buffer[i] = self.buffer[bytes_written + i];
        }
        self.buffer_end -= bytes_written;

        // Push the data into the buffer.
        let to_write = buf.len().min(BUFFER_SIZE - self.buffer_end);
        for (i, byte) in buf.iter().enumerate().take(to_write) {
            self.buffer[self.buffer_end + i] = *byte;
        }
        self.cipher
            .apply_keystream(&mut self.buffer[self.buffer_end..self.buffer_end + to_write]);

        Ok(to_write)
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
