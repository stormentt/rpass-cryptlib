use std::ffi::CStr;

mod crypto {
    use std::os::raw::{c_char, c_uchar};

    #[repr(C)]
    #[derive(Debug)]
    pub enum RC {
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
        pub fn init();
        pub fn random_bytes(len:i32) -> *const c_uchar;
        pub fn encrypt(in_s:*const c_uchar, in_len:u64, out_len:*const u64, key: *const c_char) -> *const c_uchar;
        pub fn decrypt(in_s:*const c_uchar, in_len:u64, out_len:*const u64, key: *const c_char) -> *const c_uchar;
        pub fn encrypt_file(out_path:*const c_uchar, in_path:*const c_uchar,  key: *const c_uchar) -> RC;
        pub fn decrypt_file(out_path:*const c_uchar, in_path:*const c_uchar,  key: *const c_uchar) -> RC;
    }
}

fn main() {
    let key = unsafe {
        let key_buf = crypto::random_bytes(32);
        std::slice::from_raw_parts(key_buf, 32)
    };
    print!("key: {:x?}", key);

    unsafe {
        let opath = "encrypted";
        let ipath = "plain";
        let rc = crypto::encrypt_file(opath.as_ptr(), ipath.as_ptr(), key.as_ptr());
        print!("{:?}", rc);
    }
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
