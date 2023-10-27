#include "common.h"

extern uint8_t __storfuzz_area_ptr_local[STORFUZZ_MAP_SIZE];
uint8_t       *__storfuzz_area_ptr = __storfuzz_area_ptr_local;
