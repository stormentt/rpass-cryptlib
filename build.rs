extern crate cc;

fn main() {
    cc::Build::new()
        .file("csrc/rpass-cryptlib.c")
        .file("csrc/defs.c")
        .file("csrc/encryption.c")
        .file("csrc/errors.c")
        .file("csrc/hashing.c")
        .file("csrc/streaming.c")
        .compile("librpass-cryptlib.a");
}
