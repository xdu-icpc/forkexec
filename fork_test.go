package forkexec_test

import (
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"os"
	"testing"

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
	}
}

func TestSimple(t *testing.T) {
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

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("can not get test executable path: %v", err)
	}

	pid, err := forkexec.ForkExec(exe,
		[]string{exe, "hello"},
		&forkexec.Attr{
			Env:           []string{"_GH_XDU_ICPC_FORKEXEC_TEST_HELPER_PROC_=1"},
			Files:         []uintptr{0, 1, 2},
			Seccomp:       filter,
			SetNoNewPrivs: true,
		})
	t.Logf("pid = %d", pid)
	if err != nil {
		t.Fatal(err)
	}
}
