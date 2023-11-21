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