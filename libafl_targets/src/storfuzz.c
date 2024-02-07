#include "common.h"

extern uint8_t __storfuzz_area_ptr_local[STORFUZZ_MAP_SIZE];
uint8_t       *__storfuzz_area_ptr = __storfuzz_area_ptr_local;

struct stats
{
  uint64_t total_count;
  uint64_t count_skipped;
} __storfuzz_stats = {0,0};

// This only produces meaningful results, if we are NOT using inline 
// instrumentation and define STORFUZZ_INTROSPECTION upon build 
extern struct stats __storfuzz_introspect(){
  return __storfuzz_stats;
}

inline extern void __storfuzz_record_value(uint16_t loc_id, uint8_t bitmask, uint64_t value){
#ifdef STORFUZZ_INTROSPECTION
  __storfuzz_stats.total_count++;
#endif
  // Skip pointer logic
  if((int64_t)value >= 0x400000){
#ifdef STORFUZZ_INTROSPECTION
    __storfuzz_stats.count_skipped++;
#endif
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
#ifdef STORFUZZ_INTROSPECTION
  __storfuzz_stats.total_count++;
#endif
  // Skip pointer logic
  if((int64_t)value >= 0x400000){
#ifdef STORFUZZ_INTROSPECTION
    __storfuzz_stats.count_skipped++;
#endif
    return;
  }
# ifdef STORFUZZ_LOSSY_AGGREGATION
//  uint32_t val = value;

  uint64_t res = 0;
  uint64_t even_bit = value & 0x1;
  // Set 8th result bit to 1 if negative
  uint64_t sign_bit = ((int64_t)value) < 0 ? 1 << 7 : 0;

  res |= even_bit | sign_bit;

  // Due to pointer skip, the value has at most 22 relevant bits

  value &= 0x3FFFFF;

  for( int i = 0; i < 3; i++) {
    uint8_t temp = (value >> (1 + 8 * i)) & 0xFF;
    temp = (temp >> 1) ^ temp;
    temp = (temp >> 4) ^ temp;
    temp = (temp & 0x5);
    temp = ((temp >> 1) ^ temp) & 0x3;
    res |= temp << (1 + 2 * i);
  }
  // hash in an id for the store location inside of the block
  aggregate ^= ijon_simple_hash(((uint64_t)loc_id << 8) ^ res);
# else
  // hash in an id for the store location inside of the block
  aggregate ^= ijon_simple_hash(((uint64_t)loc_id << 56) ^ value);
#endif
}

inline extern void __storfuzz_store_single_aggregated_value(uint16_t bb_id, uint8_t bitmask, uint64_t value){
  __storfuzz_aggregate_value(0, value);

  __storfuzz_store_aggregated_value(bb_id, bitmask);
}
