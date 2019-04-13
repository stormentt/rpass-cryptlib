pub fn raw_bytes(l: usize) -> Vec<u8> {
    let mut m:Vec<u8> = Vec::with_capacity(l);
    unsafe {
        m.set_len(l);
    }
    m
}
