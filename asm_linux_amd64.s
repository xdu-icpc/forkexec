#include "textflag.h"

// func asm_seccomp(flag uintptr, buf []byte, insn []bpf.RawInstruction) (err syscall.Errno)
//
// precondition: the underlying slice buf can hold at least 16 bytes
TEXT ·asm_seccomp(SB), NOSPLIT, $0-64
    MOVQ insn_len+40(FP), DI
    CMPQ DI, $4096
    JG toobig
    MOVQ buf_base+8(FP), DX
    MOVW DI, +0(DX)
    MOVQ insn_base+32(FP), DI
    MOVQ DI, +8(DX)
    MOVQ $317, AX
    MOVQ $1, DI
    MOVQ flag+0(FP), SI
    MOVQ $0, R10
    MOVQ $0, R8
    MOVQ $0, R9
    SYSCALL
    CMPQ AX, $0xfffffffffffff001
    JLS ok1
    NEGQ AX
    MOVQ AX, err+56(FP)
    RET
ok1:
    MOVQ $0, err+56(FP)
    RET
toobig:
    MOVQ $0x16, err+56(FP)
    RET

// func asm_prctl_set_no_new_privs() uintptr
TEXT ·asm_prctl_set_no_new_privs(SB), NOSPLIT, $0-8
    MOVQ $157, AX
    MOVQ $0x26, DI
    MOVQ $1, SI
    MOVQ $0, DX
    MOVQ $0, R10
    MOVQ $0, R8
    MOVQ $0, R9
    SYSCALL
    CMPQ AX, $0xfffffffffffff001
    JLS ok2
    NEGQ AX
    MOVQ AX, err+0(FP)
    RET
ok2:
    MOVQ $0, err+0(FP)
    RET
