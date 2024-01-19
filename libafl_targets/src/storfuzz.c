#include "common.h"

extern uint8_t __storfuzz_area_ptr_local[STORFUZZ_MAP_SIZE];
uint8_t       *__storfuzz_area_ptr = __storfuzz_area_ptr_local;

inline extern void __storfuzz_record_value(uint16_t loc_id, uint8_t bitmask, uint64_t value){
  // Skip pointer logic
  if((int64_t)value >= 0x400000){
    return;
  }
  uint16_t reduced = 0xff & (value ^ (value >> 8));
  __storfuzz_area_ptr[loc_id+reduced] |= bitmask;
}


// Shamelessly stolen from IJON
inline uint64_t ijon_simple_hash(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

uint64_t aggregate = 0;

inline extern void __storfuzz_store_aggregated_value(uint16_t bb_id, uint8_t bitmask){
  uint16_t reduced = 0xffff & (aggregate ^ (aggregate >> 16) ^ (aggregate >> 32) ^ (aggregate >> 48));

  __storfuzz_area_ptr[bb_id^reduced] |= bitmask;

  aggregate = 0;
}

inline extern void __storfuzz_aggregate_value(uint8_t loc_id, uint64_t value){
  // Skip pointer logic
  if((int64_t)value >= 0x400000){
    return;
  }
  // hash in an id for the store location inside of the block
  aggregate ^= ijon_simple_hash(((uint64_t)loc_id << 56) ^ value);
}

inline extern void __storfuzz_store_single_aggregated_value(uint16_t bb_id, uint8_t bitmask, uint64_t value){
  __storfuzz_aggregate_value(0, value);

  uint16_t reduced = 0xffff & (aggregate ^ (aggregate >> 16) ^ (aggregate >> 32) ^ (aggregate >> 48));

  __storfuzz_area_ptr[bb_id^reduced] |= bitmask;

  aggregate = 0;
}
