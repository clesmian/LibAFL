//! Coverage maps as static mut array

use alloc::string::String;

use crate::STORFUZZ_MAP_SIZE;

/// The map for edges.
#[no_mangle]
pub static mut __storfuzz_area_ptr_local: [u8; STORFUZZ_MAP_SIZE] = [0; STORFUZZ_MAP_SIZE];
pub use __storfuzz_area_ptr_local as STORFUZZ_MAP;


extern "C" {
    /// The area pointer points to the edges map.
    pub static mut __storfuzz_area_ptr: *mut u8;

}
pub use __storfuzz_area_ptr as STORFUZZ_MAP_PTR;

/// The size of the map for edges.
#[no_mangle]
pub static mut __storfuzz_map_size: usize = STORFUZZ_MAP_SIZE;
pub use __storfuzz_map_size as STORFUZZ_MAP_PTR_NUM;
use libafl::observers::StdMapObserver;
use libafl_bolts::ownedref::OwnedMutSlice;

/// Gets the edges map from the `STORFUZZ_MAP_PTR` raw pointer.
/// Assumes a `len` of `STORFUZZ_MAP_PTR_NUM`.
///
/// # Safety
///
/// This function will crash if `storfuzz_map_mut_ptr` is not a valid pointer.
/// The [`storfuzz_max_num`] needs to be smaller than, or equal to the size of the map.
#[must_use]
pub unsafe fn storfuzz_map_mut_slice<'a>() -> OwnedMutSlice<'a, u8> {
    OwnedMutSlice::from_raw_parts_mut(storfuzz_map_mut_ptr(), __storfuzz_map_size)
}

/// Gets a new [`StdMapObserver`] from the current [`edges_map_mut_slice`].
/// This is roughly equivalent to running:
///
/// ```rust,ignore
/// use libafl::observers::StdMapObserver;
/// use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
///
/// #[cfg(not(feature = "pointer_maps"))]
/// let observer = unsafe {
///     StdMapObserver::from_mut_ptr("edges", EDGES_MAP.as_mut_ptr(), MAX_EDGES_NUM)
/// };
/// ```
///
/// or, for the `pointer_maps` feature:
///
/// ```rust,ignore
/// use libafl::observers::StdMapObserver;
/// use libafl_targets::{EDGES_MAP_PTR, EDGES_MAP_PTR_NUM};
///
/// #[cfg(feature = "pointer_maps")]
/// let observer = unsafe {
///     StdMapObserver::from_mut_ptr("edges", EDGES_MAP_PTR, EDGES_MAP_PTR_NUM)
/// };
/// ```
///
/// # Safety
/// This will dereference [`storfuzz_map_mut_ptr`] and crash if it is not a valid address.
pub unsafe fn std_storfuzz_map_observer<'a, S>(name: S) -> StdMapObserver<'a, u8, false>
where
    S: Into<String>,
{
    StdMapObserver::from_mut_slice(name, storfuzz_map_mut_slice())
}

/// Gets the current StorFuzz map pt
/// It will usually take `STORFUZZ_MAP`, but `STORFUZZ_MAP_PTR`,
/// if built with the `pointer_maps` feature.
#[must_use]
pub fn storfuzz_map_mut_ptr() -> *mut u8 {
    unsafe {
        if cfg!(feature = "pointer_maps") {
            assert!(!STORFUZZ_MAP_PTR.is_null());
            STORFUZZ_MAP_PTR
        } else {
            STORFUZZ_MAP.as_mut_ptr()
        }
    }
}
