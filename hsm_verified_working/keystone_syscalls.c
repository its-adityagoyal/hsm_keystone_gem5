#include "keystone_syscalls.h"

int
ocall(unsigned long call_id, void* data, size_t data_len,
      void* return_buffer, size_t return_len) {
  return SYSCALL(SYSCALL_OCALL, call_id, data, data_len, return_buffer, return_len);
}

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len) {
  return SYSCALL(SYSCALL_SHAREDCOPY, dst, offset, data_len, 0, 0);
}

void
eapp_return(void) {
  SYSCALL(SYSCALL_EXIT, 0, 0, 0, 0, 0);
  __builtin_unreachable();
}
