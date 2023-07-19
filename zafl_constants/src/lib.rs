use konst::{
    primitive::parse_usize,
    result::unwrap_or as res_unwrap_or,
    option::unwrap_or as opt_unwrap_or,
};

pub const CODE_MAP_SIZE: usize = 1 << 16;

pub const DEFAULT_DATA_MAP_SIZE: usize =
    res_unwrap_or!(parse_usize(opt_unwrap_or!(option_env!("DATA_MAP_SIZE"), "")), 1 << 17);