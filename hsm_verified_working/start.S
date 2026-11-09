.section .text._start
.global _start
_start:
    call main
    j EAPP_RETURN
