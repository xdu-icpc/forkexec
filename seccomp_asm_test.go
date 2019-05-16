package forkexec

import (
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"runtime"
	"testing"
	"unsafe"

	"github.com/xdu-icpc/seccomp"
)

func TestSeccompAsm(t *testing.T) {
	rule := []bpf.Instruction{
		seccomp.LoadNr(),
		bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       unix.SYS_GETCPU,
			SkipTrue:  0,
			SkipFalse: 1,
		},
		seccomp.RetErrno(uint16(unix.ENOSYS)),
		seccomp.RetAllow(),
	}
	filter, err := bpf.Assemble(rule)
	if err != nil {
		t.Fatalf("can not assemble bpf rule: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	errno := asm_prctl_set_no_new_privs()
	if errno != 0 {
		t.Fatalf("can not set no_new_privs with prctl: %v", errno)
	}

	buf := make([]byte, 16)
	errno = asm_seccomp(0, buf, filter)
	if errno != 0 {
		t.Fatalf("can not set seccomp filter: %v", errno)
	}

	var cpu, node uint32
	_, _, err = unix.RawSyscall(unix.SYS_GETCPU,
		uintptr(unsafe.Pointer(&cpu)), uintptr(unsafe.Pointer(&node)), 0)
	if err != unix.ENOSYS {
		t.Fatalf("GETCPU didn't fail with ENOSYS: %v", err)
	}
	t.Logf("Done")
}
