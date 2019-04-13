use ::helpers;

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
