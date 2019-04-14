use ::helpers;
use ::crypto;
use std::error::Error;
use std::fs::File;
use std::io::Read;

pub fn keygen() -> Vec<u8> {
    unsafe {
        let mut buf = helpers::raw_bytes(::crypto::hash_key_len);
        ::crypto::hash_keygen(buf.as_mut_ptr());

        buf
    }
}

pub fn hash(m: &str, key: &Vec<u8>) -> Vec<u8> {
    let mlen = m.len();
    unsafe {
        let mut h = helpers::raw_bytes(::crypto::hash_len);
        let m = m.as_bytes();

        ::crypto::hash(h.as_mut_ptr(), m.as_ptr(), mlen, key.as_ptr());

        h
    }
}

pub fn check_hash(m: &str, h: &Vec<u8>, key: &Vec<u8>) -> bool {
    let mh = hash(m, key);

    unsafe {
        match ::crypto::hash_equals(mh.as_ptr(), h.as_ptr()) {
            ::crypto::RC::Success => true,
            _ => false,
        }
    }
}

pub fn hash_file(spath: &str, key: &Vec<u8>) -> Result<Vec<u8>, Box<Error>> {
    let mut source = File::open(spath)?;

    unsafe {
        let mut state = crypto::hash_state{..Default::default()};
        crypto::hash_init(&mut state, key.as_ptr());

        let mut buf = helpers::raw_bytes(::CHUNK_SIZE);
        loop {
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }

            crypto::hash_update(&mut state, buf.as_ptr(), n);
        };

        let mut out = helpers::raw_bytes(crypto::hash_len);
        crypto::hash_final(&mut state, out.as_mut_ptr());
        Ok(out)
    }
}

pub fn check_file(spath: &str, h: &Vec<u8>, key: &Vec<u8>) -> bool {
    if let Ok(mh) = hash_file(spath, key) {
        unsafe {
            match crypto::hash_equals(mh.as_ptr(), h.as_ptr()) {
                crypto::RC::Success => true,
                _ => false,
            }
        }
    } else {
        return false
    }
}
