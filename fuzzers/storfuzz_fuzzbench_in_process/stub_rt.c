#include <stdint.h>
#include <stdlib.h>

__attribute__((weak)) void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
                                                               uint32_t *stop) {
}

__attribute__((weak)) void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
}

extern void libafl_main(void);
extern int __storfuzz_original_main(int argc, char **argv);

int main(int argc, char **argv) {
  if(getenv("CONFIGURE")){
    return __storfuzz_original_main(argc, argv);
  }

  libafl_main();
  return 0;
}
