use ::helpers;
use ::crypto;
use std::error::Error;
use std::fs::File;
use std::io::{Read,Write};

pub fn keygen() -> Vec<u8> {
    unsafe {
        let mut buf = helpers::raw_bytes(::crypto::stream_key_len);
        ::crypto::stream_keygen(buf.as_mut_ptr());

        buf
    }
}

pub fn encrypt(dpath: &str, spath: &str, key: &Vec<u8>) -> Result<(), Box<Error>> {
    let mut source = File::open(spath)?;
    let mut dest = File::create(dpath)?;

    unsafe {
        let mut state:crypto::stream_state = crypto::stream_state{..Default::default()};
        let mut header = helpers::raw_bytes(crypto::stream_header_len);

        crypto::stream_init_encrypt(&mut state, header.as_mut_ptr(), key.as_ptr());
        dest.write(&header)?;

        let mut buf = helpers::raw_bytes(::CHUNK_SIZE);
        loop {
            let n = source.read(&mut buf)?;
            if n == 0 {
                break Ok(());
            }

            let mut c = helpers::raw_bytes(n + crypto::stream_abytes);
            let mut end:i8 = 0;
            if n < ::CHUNK_SIZE {
                end = 1;
            }

            let rc = crypto::stream_encrypt(&mut state, c.as_mut_ptr(), buf.as_ptr(), n, end);
            if rc != crypto::RC::Success {
                return Err(Box::new(::Error::new(rc)));
            }
            dest.write(&c)?;
        }
    }
}

pub fn decrypt(dpath: &str, spath: &str, key: &Vec<u8>) -> Result<(), Box<Error>> {
    let mut source = File::open(spath)?;
    let mut dest = File::create(dpath)?;

    unsafe {
        let mut state:crypto::stream_state = crypto::stream_state{..Default::default()};
        let mut header = helpers::raw_bytes(crypto::stream_header_len);

        source.read(&mut header)?;
        let rc = crypto::stream_init_decrypt(&mut state, header.as_mut_ptr(), key.as_ptr());
        if rc != crypto::RC::Success {
            return Err(Box::new(::Error::new(rc)));
        }

        let mut buf = helpers::raw_bytes(::CHUNK_SIZE + crypto::stream_abytes);
        loop {
            let n = source.read(&mut buf)?;
            if n == 0 {
                break Ok(());
            }

            let mut m = helpers::raw_bytes(n - crypto::stream_abytes);
            let mut end:i8 = 0;

            let rc = crypto::stream_decrypt(&mut state, m.as_mut_ptr(), buf.as_ptr(), n, &mut end);
            if rc != crypto::RC::Success {
                return Err(Box::new(::Error::new(rc)));
            }

            dest.write(&m)?;
            if end == 1 {
                break Ok(());
            }
        }
    }
}
