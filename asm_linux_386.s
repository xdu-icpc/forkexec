#include "textflag.h"

// func asm_seccomp(flag uintptr, buf []byte, insn []bpf.RawInstruction) (err syscall.Errno)
//
// precondition: the underlying slice buf can hold at least 16 bytes
TEXT ·asm_seccomp(SB), NOSPLIT, $0-32
    MOVL insn_len+20(FP), DI
    CMPL DI, $4096
    JG toobig
    MOVL buf_base+4(FP), DX
    MOVW DI, +0(DX)
    MOVL insn_base+16(FP), DI
    MOVL DI, +4(DX)
    MOVL $354, AX
    MOVL $1, BX
    MOVL flag+0(FP), CX
    MOVL $0, SI
    MOVL $0, DI
    INT $0x80
    CMPL AX, $0xfffff001
    JLS ok1
    NEGL AX
    MOVL AX, err+28(FP)
    RET
ok1:
    MOVL $0, err+28(FP)
    RET
toobig:
    MOVL $0x16, err+28(FP)
    RET

// func asm_prctl_set_no_new_privs() uintptr
TEXT ·asm_prctl_set_no_new_privs(SB), NOSPLIT, $0-4
    MOVL $172, AX
    MOVL $0x26, BX
    MOVL $1, CX
    MOVL $0, DX
    MOVL $0, SI
    MOVL $0, DI
    INT $0x80
    CMPL AX, $0xfffff001
    JLS ok2
    NEGL AX
    MOVL AX, err+0(FP)
    RET
ok2:
    MOVL $0, err+0(FP)
    RET
