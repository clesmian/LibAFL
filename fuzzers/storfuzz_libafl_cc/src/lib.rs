use std::env::var;
use libafl_bolts::ctor;
use libafl_targets::{map_shared_memory, start_forkserver};

#[cfg(feature = "auto_init_forkserver")]
#[ctor]
fn constructor(){
    if var("BE_QUIET_ITS_BUILD_TIME").is_err() {
        println!("LIBAFL_FORKSERVER_AUTO_INIT");
    }
    libafl_start_forkserver();
}

#[no_mangle]
pub extern "C" fn libafl_start_forkserver() {
    // Map shared memory region for the edge coverage map
    map_shared_memory();
    // Start the forkserver
    start_forkserver();
}
