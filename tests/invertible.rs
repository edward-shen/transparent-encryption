use std::io::{Read, Write};

use chacha20::ChaCha20;
use cipher::generic_array::GenericArray;
use transparent_encryption::{Reader, Writer};

const DATA: &[u8; 16384] = include_bytes!("rand_data");

#[test]
fn writer_and_reader_are_invertible() -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![];
    let key = &GenericArray::from([1; 32]);
    let nonce = &GenericArray::from([1; 12]);
    {
        let mut encrypted_writer =
            Writer::<_, ChaCha20, 4096>::new_from_parts(&mut buffer, key, nonce);
        encrypted_writer.write_all(DATA)?;
    }
    assert_ne!(buffer, DATA);

    let mut encrypted_reader = Reader::<_, ChaCha20>::new_from_parts(&*buffer, key, nonce);
    let mut output = vec![];
    encrypted_reader.read_to_end(&mut output)?;
    assert_eq!(output, DATA);

    Ok(())
}
