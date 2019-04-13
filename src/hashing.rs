use ::helpers;

pub fn keygen() -> Vec<u8> {
    unsafe {
        let mut buf = helpers::raw_bytes(::crypto::hash_key_len);
        ::crypto::hash_keygen(buf.as_mut_ptr());

        buf
    }
}
