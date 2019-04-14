#![allow(dead_code)]
use std::ffi::CStr;

pub mod simple;
pub mod hashing;
pub mod helpers;
pub mod streaming;

static CHUNK_SIZE:usize = 16 * 1024 * 1024;

mod crypto {
    use std::os::raw::{c_char, c_uchar};

    type CBytes = *const c_uchar;
    type CBytesMut = *mut c_uchar;
    type CBytesLen = usize;

    #[repr(C)]
    #[derive(Debug, PartialEq)]
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
    impl Default for hash_state {
        fn default() -> Self {
            hash_state {
                opaque: [0; 384],
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, Default)]
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
        pub fn hash_equals(m1: CBytes, m2: CBytes) -> RC;

        // rpass-cryptlib.c
        pub fn init() -> RC;

        // streaming.c
        pub fn stream_keygen(buf: CBytesMut);
        pub fn stream_init_encrypt(state: *mut stream_state, header: CBytesMut, key: CBytes);
        pub fn stream_encrypt(state: *mut stream_state, c: CBytesMut, m: CBytes, mlen: CBytesLen, end: i8) -> RC;

        pub fn stream_init_decrypt(state: *mut stream_state, header: CBytesMut, key: CBytes) -> RC;
        pub fn stream_decrypt(state: *mut stream_state, m: CBytesMut, c: CBytes, clen: CBytesLen, end: *const i8) -> RC;
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

#[cfg(test)]
mod tests {
    use simple;
    use hashing;
    use streaming;

    #[test]
    fn simple() {
        ::init();
        let key = simple::keygen();
        let plaintext = "hello world!";

        let ciphertext = simple::encrypt(&plaintext, &key).unwrap();
        let decrypted = simple::decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn hash() {
        ::init();
        let key = hashing::keygen();

        let m1 = "hello world!";
        let m2 = "nope!";
        let m3 = "hello world!";

        let h1 = hashing::hash(&m1, &key);
        let h2 = hashing::hash(&m2, &key);
        let h3 = hashing::hash(&m3, &key);

        assert_eq!(h1, h3);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_file() {
        ::init();
        let key = hashing::keygen();

        let hash = hashing::hash_file("plaintext", &key).unwrap();
        let matched = hashing::check_file("plaintext", &hash, &key);
        assert!(matched == true);
    }

    #[test]
    fn streaming() {
        ::init();
        let key = streaming::keygen();

        streaming::encrypt("encrypted", "plaintext", &key).unwrap();
        streaming::decrypt("decrypted", "encrypted", &key).unwrap();
    }
}
