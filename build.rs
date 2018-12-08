extern crate cc;

fn main() {
    cc::Build::new()
        .file("csrc/rpass-cryptlib.c")
        .compile("librpass-cryptlib.a");
}
