use std::ffi::{CStr,CString};

mod crypto {
    use std::os::raw::{c_char, c_uchar};

    #[repr(C)]
    #[derive(Debug)]
    pub enum rc {
        Success,
        SodiumInitError,

        DecryptionError,
        EncryptionError,

        InputHeaderInvalid,
        InputHeaderReadError,
        InputOpenError,
        InputPrematureEOF,
        InputReadError,

        OutputCloseError,
        OutputOpenError,
        OutputWriteError,
    }

    #[link(name="rpass-cryptlib", kind="static")]
    extern "C" {
        pub fn random_bytes(len:usize) -> *const c_uchar;
        pub fn encrypt(in_s:*const c_char, in_len:usize, out_len:*const u64, key: *const c_uchar) -> *const c_uchar;
        pub fn decrypt(in_s:*const c_uchar, in_len:usize, out_len:*const u64, key: *const c_uchar) -> *const c_char;
        pub fn encrypt_file(out_path:*const c_char, in_path:*const c_char,  key: *const c_uchar) -> rc;
        pub fn decrypt_file(out_path:*const c_char, in_path:*const c_char,  key: *const c_uchar) -> rc;
    }
}

fn random_bytes(len:usize) -> Vec<u8> {
    unsafe {
        let key = crypto::random_bytes(len);
        std::slice::from_raw_parts(key, len).to_owned()
    }
}

fn encrypt(m:&str, key:&Vec<u8>) -> Vec<u8> {
    let mlen = m.len();
    let mut out_len:u64 = 0;
    unsafe {
        let m = CString::new(m).unwrap();
        let c = crypto::encrypt(m.as_ptr(), mlen, &mut out_len, key.as_ptr());
        std::slice::from_raw_parts(c, out_len as usize).to_owned()
    }
}

fn decrypt(c:&Vec<u8>, key:&Vec<u8>) -> String {
    let clen = c.len();
    let mut out_len:u64 = 0;
    unsafe {
        let m = crypto::decrypt(c.as_ptr(), clen, &mut out_len, key.as_ptr());
        CStr::from_ptr(m).to_string_lossy().into_owned()
    }
}

fn encrypt_file(out_path:&str, in_path:&str, key:&Vec<u8>) -> crypto::rc {
    unsafe {
        let out_path = CString::new(out_path).unwrap();
        let in_path = CString::new(in_path).unwrap();
        crypto::encrypt_file(out_path.as_ptr(), in_path.as_ptr(), key.as_ptr())
    }
}

fn decrypt_file(out_path:&str, in_path:&str, key:&Vec<u8>) -> crypto::rc {
    unsafe {
        let out_path = CString::new(out_path).unwrap();
        let in_path = CString::new(in_path).unwrap();
        crypto::decrypt_file(out_path.as_ptr(), in_path.as_ptr(), key.as_ptr())
    }
}

fn main() {
    let key = random_bytes(32);
    print!("key: {:x?}\n", key);
    let erc = encrypt_file("encrypted", "plain", &key);
    print!("{:?}\n", erc);
    let drc = decrypt_file("decrypted", "encrypted", &key);
    print!("{:?}\n", drc);

    let encrypted = encrypt("test!", &key);
    print!("encrypted: {:x?}\n", encrypted);
    let decrypted = decrypt(&encrypted, &key);

    print!("decrypted: {}\n", decrypted);
}
#[cfg(test)]
mod tests {
    #[test]
    fn test_string_encryption() {
        let key_str = unsafe {
            let key_buf = ::random_bytes(32);
            let key_cstr = CStr::from_ptr(key_buf);
            let key_str = key_cstr.to_str().unwrap();
            key_str.to_owned()
        };
        print!("{}", key_str);
    }
}
