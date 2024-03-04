fn main() {
    cxx_build::bridge("src/vaas.rs").compile("vaas");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/vaas.rs");
}
