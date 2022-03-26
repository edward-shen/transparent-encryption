#![cfg(feature = "tokio")]

use std::io::Write;

use chacha20::ChaCha20;
use cipher::generic_array::GenericArray;
use tokio::io::AsyncWriteExt;
use transparent_encryption::{AsyncBufWriter, BufWriter};

const DATA: &[u8; 16384] = include_bytes!("rand_data");

#[tokio::test]
async fn writer_and_reader_are_invertible() -> Result<(), Box<dyn std::error::Error>> {
    let mut sync_buffer = vec![];
    let mut async_buffer = vec![];
    let key = &GenericArray::from([1; 32]);
    let nonce = &GenericArray::from([1; 12]);

    {
        let mut sync_writer =
            BufWriter::<_, ChaCha20>::new_from_parts(&mut sync_buffer, key, nonce);
        sync_writer.write_all(DATA)?;
        sync_writer.flush()?;

        let mut async_writer =
            AsyncBufWriter::<_, ChaCha20>::new_from_parts(&mut async_buffer, key, nonce);
        async_writer.write_all(DATA).await?;
        async_writer.flush().await?;
    }

    assert_eq!(sync_buffer, async_buffer);

    Ok(())
}
