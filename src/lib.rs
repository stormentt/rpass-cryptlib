#![allow(dead_code)]
use std::ffi::CStr;

mod crypto {
    use std::os::raw::{c_char, c_uchar};

    type CBytes = *const c_uchar;
    type CBytesMut = *mut c_uchar;
    type CBytesLen = usize;

    #[repr(C)]
    #[derive(Debug)]
    pub enum RC {
        Success,
        SodiumInitError,

        DecryptionError,
        EncryptionError,
        HashingError,

        HeaderInvalid,

        MessageTooLong,
        HashMismatch,
    }

    #[repr(C, align(64))]
    #[derive(Copy, Clone)]
    pub struct hash_state {
        pub opaque: [c_uchar; 384usize],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct stream_state {
        pub k: [c_uchar; 32usize],
        pub nonce: [c_uchar; 12usize],
        pub _pad: [c_uchar; 8usize],
    }

    #[link(name="rpass-cryptlib", kind="static")]
    extern "C" {
        // defs.c
        pub static encryption_abytes: usize;
        pub static encryption_key_len: usize;
        pub static encryption_nonce_len: usize;

        pub static stream_header_len: usize;
        pub static stream_key_len: usize;
        pub static stream_abytes: usize;

        pub static hash_key_len: usize;
        pub static hash_len: usize;

        // encryption.c
        pub fn encryption_keygen(buf: CBytesMut);
        pub fn encrypt(c: CBytesMut, m: CBytes, mlen: CBytesLen, key: CBytes);
        pub fn decrypt(m: CBytesMut, c: CBytes, clen: CBytesLen, key: CBytes) -> RC;
        
        // errors.c
        pub fn rc2str(rc:RC) -> *const c_char;

        // hashing.c
        pub fn hash_keygen(buf: CBytesMut);
        pub fn hash(out: CBytes, m: CBytes, mlen: CBytesLen, key: CBytes);
        pub fn hash_init(state: *mut hash_state, key: CBytes);
        pub fn hash_update(state: *mut hash_state, m: CBytes, m_len: CBytesLen);
        pub fn hash_final(state: *mut hash_state, out: CBytesMut);
        pub fn hash_equals(m1: CBytes, m2: CBytes);

        // rpass-cryptlib.c
        pub fn init() -> RC;

        // streaming.c
        pub fn stream_keygen(buf: CBytesMut);
        pub fn stream_init_encrypt(state: *mut stream_state, header: CBytes, key: CBytes);
        pub fn stream_encrypt(state: *mut stream_state, c: CBytesMut, m: CBytes, mlen: CBytes, end: i8) -> RC;

        pub fn stream_init_decrypt(state: *mut stream_state, header: CBytes, key: CBytes) -> RC;
        pub fn stream_decrypt(state: *mut stream_state, m: CBytesMut, c: CBytes, clen: CBytes, end: *const i8) -> RC;
    }
}

#[derive(Debug)]
pub struct Error {
    msg: String,
}

impl Error {
    fn new(rc: crypto::RC) -> Error {
        let errstr = unsafe {
            let ret = crypto::rc2str(rc);
            CStr::from_ptr(ret).to_string_lossy().into_owned()
        };

        Error{msg:errstr}
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f,"{}",self.msg)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.msg
    }
}

pub fn init() {
    unsafe {
        crypto::init();
    }
}

pub fn encryption_keygen() -> Vec<u8> {
    unsafe {
        let mut buf:Vec<u8> = Vec::with_capacity(crypto::encryption_key_len);
        crypto::encryption_keygen(buf.as_mut_ptr());
        buf.set_len(crypto::encryption_key_len);

        buf
    }
}

pub fn encrypt(m:&str, key:&Vec<u8>) -> Result<Vec<u8>, Error> {
    let mlen = m.len();
    unsafe {
        let clen = mlen + crypto::encryption_abytes;
        let mut c:Vec<u8> = Vec::with_capacity(clen);
        c.set_len(clen);
        let m = m.as_bytes();

        crypto::encrypt(c.as_mut_ptr(), m.as_ptr(), mlen, key.as_ptr());
        Ok(c)
    }
}

pub fn decrypt(c:&Vec<u8>, key:&Vec<u8>) -> Result<String, Error> {
    let clen = c.len();
    unsafe {
        if clen < crypto::encryption_abytes {
            return Err(Error::new(crypto::RC::DecryptionError))
        }

        let mlen = clen - crypto::encryption_abytes;

        let mut m:Vec<u8> = Vec::with_capacity(mlen);
        m.set_len(mlen);
        let rc = crypto::decrypt(m.as_mut_ptr(), c.as_ptr(), clen, key.as_ptr());
        match rc {
            crypto::RC::Success => Ok(String::from_utf8(m).unwrap()),
            _ => Err(Error::new(rc)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn string_encryption() {
        ::init();
        let key = ::encryption_keygen();
        let plaintext = "hello world!";

        let ciphertext = ::encrypt(&plaintext, &key).unwrap();
        let decrypted = ::decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
