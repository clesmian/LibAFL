use konst::{
    primitive::parse_usize,
    result::unwrap_or as res_unwrap_or,
    option::unwrap_or as opt_unwrap_or,
};

pub const CODE_MAP_SIZE: usize = 1 << 17;

pub const DEFAULT_DATA_MAP_SIZE: usize =
    res_unwrap_or!(parse_usize(opt_unwrap_or!(option_env!("DATA_MAP_SIZE"), "")), 1 << 17);

/*
 abort_on_error=1 -> do not exit cleanly (we cannot detect it as a crash otherwise)
 detect_leaks=0 -> ignore memory leaks (we only care about unsafe accesses)
 malloc_context_size=0 -> performance optimization (do not remember where allocations came from)
 symbolize=0 -> performance optimization (we don't keep the output, so we do not care about the actual function names)
 allocator_may_return_null=1 -> don't crash when running OOM
 */
pub const DEFAULT_ASAN_OPTIONS: String =
       "abort_on_error=1:\
        detect_leaks=0:\
        malloc_context_size=0:\
        symbolize=0:\
        allocator_may_return_null=1".to_string();
