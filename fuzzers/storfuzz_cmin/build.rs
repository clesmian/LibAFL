fn main() {
    if(option_env!("FUZZBENCH").is_some()) {
        println!("cargo:rustc-link-lib=c++");
    }
}