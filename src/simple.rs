use ::helpers;

pub fn keygen() -> Vec<u8> {
    unsafe {
        let mut buf = helpers::raw_bytes(::crypto::encryption_key_len);
        ::crypto::encryption_keygen(buf.as_mut_ptr());

        buf
    }
}

pub fn encrypt(m:&str, key:&Vec<u8>) -> Result<Vec<u8>, ::Error> {
    let mlen = m.len();
    unsafe {
        let clen = mlen + ::crypto::encryption_abytes;
        let mut c = helpers::raw_bytes(clen);

        let m = m.as_bytes();

        ::crypto::encrypt(c.as_mut_ptr(), m.as_ptr(), mlen, key.as_ptr());
        Ok(c)
    }
}

pub fn decrypt(c:&Vec<u8>, key:&Vec<u8>) -> Result<String, ::Error> {
    let clen = c.len();
    unsafe {
        if clen < ::crypto::encryption_abytes {
            return Err(::Error::new(::crypto::RC::DecryptionError))
        }

        let mlen = clen - ::crypto::encryption_abytes;
        let mut m = helpers::raw_bytes(mlen);

        let rc = ::crypto::decrypt(m.as_mut_ptr(), c.as_ptr(), clen, key.as_ptr());
        match rc {
            ::crypto::RC::Success => Ok(String::from_utf8(m).unwrap()),
            _ => Err(::Error::new(rc)),
        }
    }
}
