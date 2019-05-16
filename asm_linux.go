package forkexec

import (
	"golang.org/x/net/bpf"
	"syscall"
)

// An assembly function with "nosplit" attribute to be used in fork child.
func asm_seccomp(flag uintptr, buf []byte, insn []bpf.RawInstruction) (err syscall.Errno)

func asm_prctl_set_no_new_privs() (err syscall.Errno)
