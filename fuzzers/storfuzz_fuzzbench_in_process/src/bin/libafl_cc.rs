use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses, ToolWrapper};

pub fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        dir.pop();

        if env::var("AFL_LLVM_DICT2FILE").is_err() && env::var("AUTODICT_IN_BINARY").is_err(){
            env::set_var("AFL_LLVM_DICT2FILE", env::current_dir().unwrap().join("libafl.dict").as_os_str());
        }
        // Must be always present, even without --libafl
        args.push("-fsanitize-coverage=trace-pc-guard".into());

        let mut cc = ClangWrapper::new();

        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        cc.add_pass(LLVMPasses::AutoTokens);

        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            // add arguments only if --libafl or --libafl-no-link are present
            .need_libafl_arg(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .add_pass(LLVMPasses::StorFuzzCoverage)
            .link_staticlib(&dir, "storfuzz_fuzzbench_in_process")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
