use std::error::Error;

fn build_and_link_safe_alloc(){
    #[cfg(feature="safe_alloc_in_process")]
    {
        println!("cargo:rerun-if-changed=c_src/safe_alloc.c");

        cc::Build::new()
            .file("c_src/safe_alloc.c")
            .shared_flag(true)
            .opt_level(2)
            .flag("-fpic")
            .flag("-std=c11")
            .flag("-Wall")
            .flag("-Werror")
            .flag("-Wextra")
            .flag("-ldl")
            .compile("safe_alloc");

        println!("cargo:rustc-link-lib=libsafe_alloc");
    }
}

#[rustversion::nightly]
#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=nightly");

    build_and_link_safe_alloc();

    Ok(())
}

#[rustversion::not(nightly)]
#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    assert!(
        cfg!(all(not(docrs), not(feature = "nautilus"))),
        "The 'nautilus' feature of libafl requires a nightly compiler"
    );

    build_and_link_safe_alloc();
    Ok(())
}