use std::ffi::{CStr,CString};

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
        pub fn rc2str(rc:RC) -> *const c_char;

        pub fn encrypt_overhead() -> usize;
        pub fn encrypt_keysize() -> usize;
        pub fn file_encrypt_keysize() -> usize;

        pub fn random_bytes(buf:*const c_uchar, len:usize) -> RC;
        pub fn random_alphanum(buf:*const c_uchar, len:usize) -> RC;

        pub fn encrypt(out_buf:*const c_uchar, in_buf:*const c_char, in_len:usize, key: *const c_uchar) -> RC;
        pub fn decrypt(out_buf:*const c_uchar, in_buf:*const c_uchar, in_len:usize, key: *const c_uchar) -> RC;

        pub fn encrypt_file(out_path:*const c_char, in_path:*const c_char,  key: *const c_uchar) -> RC;
        pub fn decrypt_file(out_path:*const c_char, in_path:*const c_char,  key: *const c_uchar) -> RC;
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

fn random_bytes(len:usize) -> Result<Vec<u8>, Error> {
    unsafe {
        let mut buf:Vec<u8> = Vec::with_capacity(len);
        let rc = crypto::random_bytes(buf.as_mut_ptr(), len);
        buf.set_len(len);

        match rc {
            crypto::RC::Success => Ok(buf),
            _ => Err(Error::new(rc)),
        }
    }
}

fn random_key() -> Result<Vec<u8>, Error> {
    random_bytes(32)
}

fn random_alphanum(len:usize) -> Result<String, Error> {
    unsafe {
        let mut buf:Vec<u8> = Vec::with_capacity(len);
        let rc = crypto::random_alphanum(buf.as_mut_ptr(), len);
        buf.set_len(len);
        match rc {
            crypto::RC::Success => {
                let randstr = String::from_utf8(buf).unwrap();
                Ok(randstr)
            },
            _ => Err(Error::new(rc)),
        }
    }
}

fn encrypt(m:&str, key:&Vec<u8>) -> Result<Vec<u8>, Error> {
    let mlen = m.len();
    unsafe {
        let outlen = mlen + crypto::encrypt_overhead();
        let mut outbuf:Vec<u8> = Vec::with_capacity(outlen);
        outbuf.set_len(outlen);
        let m = CString::new(m).unwrap();

        let rc = crypto::encrypt(outbuf.as_mut_ptr(), m.as_ptr(), mlen, key.as_ptr());
        match rc {
            crypto::RC::Success => Ok(outbuf),
            _ => Err(Error::new(rc)),
        }
    }
}

fn decrypt(c:&Vec<u8>, key:&Vec<u8>) -> Result<String, Error> {
    let clen = c.len();
    unsafe {
        if clen < crypto::encrypt_overhead() {
            return Err(Error::new(crypto::RC::DecryptionError))
        }

        let outlen = clen - crypto::encrypt_overhead();

        let mut outbuf:Vec<u8> = Vec::with_capacity(outlen);
        outbuf.set_len(outlen);
        let rc = crypto::decrypt(outbuf.as_mut_ptr(), c.as_ptr(), clen, key.as_ptr());
        match rc {
            crypto::RC::Success => Ok(String::from_utf8(outbuf).unwrap()),
            _ => Err(Error::new(rc)),
        }
    }
}

fn encrypt_file(out_path:&str, in_path:&str, key:&Vec<u8>) -> Result<(), Error> {
    unsafe {
        let out_path = CString::new(out_path).unwrap();
        let in_path = CString::new(in_path).unwrap();
        let rc = crypto::encrypt_file(out_path.as_ptr(), in_path.as_ptr(), key.as_ptr());
        match rc {
            crypto::RC::Success => Ok(()),
            _ => Err(Error::new(rc)),
        }
    }
}

fn decrypt_file(out_path:&str, in_path:&str, key:&Vec<u8>) -> Result<(), Error> {
    unsafe {
        let out_path = CString::new(out_path).unwrap();
        let in_path = CString::new(in_path).unwrap();
        let rc = crypto::decrypt_file(out_path.as_ptr(), in_path.as_ptr(), key.as_ptr());
        match rc {
            crypto::RC::Success => Ok(()),
            _ => Err(Error::new(rc)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File,create_dir};
    use std::io::{Read,Write};
    use std::env::temp_dir;

    #[test]
    fn random_bytes() {
        let bytes = ::random_bytes(128).unwrap();
        assert!(bytes.len() == 128);
    }

    #[test]
    fn random_alphanum() {
        let st = ::random_alphanum(32).unwrap();
        assert!(st.len() == 32);
    }

    #[test]
    fn string_encryption() {
        let key = ::random_key().unwrap();
        let plaintext = "hello world!";

        let ciphertext = ::encrypt(&plaintext, &key).unwrap();
        let decrypted = ::decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn file_encryption() {
        let mut tmpdir = temp_dir();
        tmpdir.push("rust-cryptlib-testfiles");
        create_dir(&tmpdir);

        let mut plaintext = tmpdir.clone();
        plaintext.push("plaintext");
        let mut encrypted = tmpdir.clone();
        encrypted.push("encrypted");
        let mut decrypted = tmpdir.clone();
        decrypted.push("decrypted");

        let key = ::random_key().unwrap();
        let test_bytes = ::random_bytes(1024 * 1024 * 10).unwrap(); // 10 MiB

        {
            let mut file = File::create(&plaintext).unwrap();
            file.write_all(&test_bytes);
        }

        if let Err(err) = ::encrypt_file(encrypted.to_str().unwrap(), plaintext.to_str().unwrap(), &key) {
            assert!(false, err);
        }

        if let Err(err) = ::decrypt_file(decrypted.to_str().unwrap(), encrypted.to_str().unwrap(), &key) {
            assert!(false, err);
        }

        {
            let mut file = File::open(&decrypted).unwrap();
            let mut read_bytes = vec!(0 as u8; 0);
            file.read_to_end(&mut read_bytes).unwrap();

            assert_eq!(read_bytes, test_bytes);
        }

        std::fs::remove_dir_all(&tmpdir);
    }
}
