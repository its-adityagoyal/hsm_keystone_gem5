#ifndef KEYSTONE_SYSCALLS_H
#define KEYSTONE_SYSCALLS_H

#include <stddef.h>
#include <stdint.h>

#define SYSCALL_OCALL 1001
#define SYSCALL_SHAREDCOPY 1002
#define SYSCALL_ATTEST_ENCLAVE 1003
#define SYSCALL_GET_SEALING_KEY 1004
#define SYSCALL_EXIT 1101

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);      \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);      \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);      \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);      \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);      \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);     \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7)\
                 : "memory");                                  \
    a0;                                                        \
  })

int ocall(unsigned long call_id, void* data, size_t data_len,
          void* return_buffer, size_t return_len);

int copy_from_shared(void* dst, uintptr_t offset, size_t data_len);

void eapp_return(void);

#endif
