fn main() {
    cxx_build::bridge("src/vaas.rs").compile("vaas");
    println!("cargo:rerun-if-changed=src/lib.rs");
}