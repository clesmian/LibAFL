use konst::{
    primitive::parse_usize,
    result::unwrap_ctx,
    option::unwrap_or,
};

pub const CODE_MAP_SIZE: usize = 1 << 16;
pub const DEFAULT_DATA_MAP_SIZE: usize = unwrap_ctx!(parse_usize(unwrap_or!(option_env!("DATA_MAP_SIZE"), "131072"))); // 1<<17 = 131072