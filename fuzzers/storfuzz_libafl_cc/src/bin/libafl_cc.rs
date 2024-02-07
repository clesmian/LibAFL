use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses, ToolWrapper};

pub fn main() {
    let args: Vec<String> = env::args().collect();
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

        let mut cc = ClangWrapper::new();
        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            // Enable libafl's coverage instrumentation
            .add_pass(LLVMPasses::AFLCoverage)
            .add_pass(LLVMPasses::AutoTokens)
            .add_pass(LLVMPasses::StorFuzzCoverage)
            // .add_arg("-mllvm")
            // .add_arg("-ctx") // Context sensitive coverage
            // Imitate afl-cc's compile definitions
            .add_arg("-D__AFL_FUZZ_INIT()=int __afl_sharedmem_fuzzing = 1;extern unsigned int *__afl_fuzz_len;extern unsigned char *__afl_fuzz_ptr;unsigned char __afl_fuzz_alt[1048576];unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;void libafl_start_forkserver(void)")
            .add_arg("-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : __afl_fuzz_alt_ptr)")
            .add_arg("-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : (*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff ? 0 : *__afl_fuzz_len)")
            .add_arg("-D__AFL_INIT()=libafl_start_forkserver()") // Not really needed as it is auto-initialized by constructor
            // Link with libafl's forkserver implementation
            .link_staticlib(&dir, "libforkserver_storfuzz_cc")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}