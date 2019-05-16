package forkexec

import (
	"golang.org/x/net/bpf"
	"syscall"
)

type Attr struct {
	Dir           string               // Current working directory.
	Env           []string             // Environment.
	Files         []uintptr            // File descriptors.
	Chroot        string               // Chroot.
	Setpgid       bool                 // Set process group ID to Pgid, or new pid if Pgid == 0.
	Pdeathsig     syscall.Signal       // Signal that the process will get when its parent dies.
	Pgid          int                  // Child's process group ID if Setpgid.
	Cloneflags    uintptr              // Flags for clone calls.
	Seccomp       []bpf.RawInstruction // The BPF seccomp syscall filter.  Requires the no_new_privs attribute.
	SeccompFlags  uintptr              // Flags for seccomp calls.
	SetNoNewPrivs bool                 // Set the process' no_new_privs attribute.
	buf           [16]byte
}
