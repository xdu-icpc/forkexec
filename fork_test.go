package forkexec_test

import (
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/xdu-icpc/forkexec"
	"github.com/xdu-icpc/seccomp"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("_GH_XDU_ICPC_FORKEXEC_TEST_HELPER_PROC_") != "1" {
		t.Skip()
	}
	defer os.Exit(0)

	switch os.Args[1] {
	case "hello":
		fmt.Println("Hello")
	case "getcpu":
		var cpu, node uint32
		_, _, err := syscall.RawSyscall(unix.SYS_GETCPU,
			uintptr(unsafe.Pointer(&cpu)),
			uintptr(unsafe.Pointer(&node)),
			0)
		fmt.Println(err)
		if err != syscall.ENOSYS {
			os.Exit(1)
		}
	}
}

func TestForkExec(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("can not get test executable path: %v", err)
	}

	basicAttr := forkexec.Attr{
		Files: []uintptr{0, 1, 2},
		Env:   []string{"_GH_XDU_ICPC_FORKEXEC_TEST_HELPER_PROC_=1"},
	}

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

	secAttr := basicAttr
	secAttr.Seccomp, err = bpf.Assemble(rule)

	tests := []struct {
		name string
		argv []string
		attr *forkexec.Attr
	}{
		{
			name: "TestSimple",
			argv: []string{exe, "hello"},
			attr: &basicAttr,
		},
		{
			name: "TestSeccomp1",
			argv: []string{exe, "hello"},
			attr: &secAttr,
		},
		{
			name: "TestSeccomp2",
			argv: []string{exe, "getcpu"},
			attr: &secAttr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(*testing.T) {
			pid, err := forkexec.ForkExec(test.argv[0], test.argv, test.attr)
			if err != nil {
				t.Fatal(err)
			}
			var wstat syscall.WaitStatus
			_, err = syscall.Wait4(pid, &wstat, 0, nil)
			t.Logf("pid = %d, stat = %v", pid, wstat)
		})
	}
}
