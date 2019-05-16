package forkexec

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

type childState int

const (
	childStateUnknown childState = iota
	childStateSetpgid
	childStateChroot
	childStateChdir
	childStatePdeathsig
	childStateNoNewPrivs
	childStateDup
	childStateClearCloexec
	childStateSeccomp
	childStateExec
)

var stateStr = []string{
	"failed to get state from child",
	"setpgid",
	"chroot",
	"chdir",
	"can not set parent death signal: prctl",
	"can not set no_new_privs: prctl",
	"dup",
	"can not clear FD_CLOEXEC: fcntl",
	"seccomp",
	"exec",
}

func (s childState) String() string {
	if s < 0 || int(s) >= len(stateStr) {
		return "unknown"
	}
	return stateStr[s]
}

type childStatus struct {
	state childState
	errno syscall.Errno
}

func (s childStatus) String() string {
	return fmt.Sprintf("%v: %v", s.state, s.errno)
}

type childError struct {
	pid    int
	status childStatus
}

func (e childError) Error() string {
	return fmt.Sprintf("child (pid = %d) fails: %v", e.pid, e.status)
}

var zeroAttr Attr

func forkExec(argv0 string, argv []string, attr *Attr) (pid int, err error) {
	var (
		p       [2]int
		n       int
		err1    syscall.Errno
		buf     [32]byte
		wstatus syscall.WaitStatus
		cstatus childStatus
	)

	if attr == nil {
		attr = &zeroAttr
	}

	argv0p, err := syscall.BytePtrFromString(argv0)
	if err != nil {
		return 0, err
	}

	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return 0, err
	}

	envvp, err := syscall.SlicePtrFromStrings(attr.Env)
	if err != nil {
		return 0, err
	}

	var chroot *byte
	if attr.Chroot != "" {
		chroot, err = syscall.BytePtrFromString(attr.Chroot)
		if err != nil {
			return 0, err
		}
	}

	var dir *byte
	if attr.Dir != "" {
		dir, err = syscall.BytePtrFromString(attr.Dir)
		if err != nil {
			return 0, err
		}
	}

	syscall.ForkLock.Lock()
	err = syscall.Pipe2(p[:], syscall.O_CLOEXEC)
	if err != nil {
		syscall.ForkLock.Unlock()
		return 0, err
	}

	pid, err1 = doForkExec(argv0p, argvp, envvp, chroot, dir, attr, p[1])
	syscall.ForkLock.Unlock()

	syscall.Close(p[1])
	if err1 != 0 {
		err = syscall.Errno(err1)
		syscall.Close(p[0])
		return 0, err
	}

	p0 := os.NewFile(uintptr(p[0]), "child|")
	n, err = p0.Read(buf[:])
	p0.Close()
	if err != io.EOF || n != 0 {
		if n == int(unsafe.Sizeof(childStatus{})) {
			cstatus = *(*childStatus)(unsafe.Pointer(&buf[0]))
		} else {
			cstatus = childStatus{
				state: childStateUnknown,
				errno: syscall.EPIPE,
			}
		}
		err = childError{
			pid:    pid,
			status: cstatus,
		}
		_, err1 := syscall.Wait4(pid, &wstatus, 0, nil)
		for err1 == syscall.EINTR {
			_, err1 = syscall.Wait4(pid, &wstatus, 0, nil)
		}
		return 0, err
	}

	return pid, nil
}

//go:norace
func doForkExec(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *Attr, pipe int) (pid int, err syscall.Errno) {
	r1, err1, _, locked := doForkExec1(argv0, argv, envv, chroot, dir, attr, pipe)
	if locked {
		runtime_AfterFork()
	}
	if err1 != 0 {
		return 0, err1
	}

	pid = int(r1)
	return pid, 0
}

//go:noinline
//go:norace
func doForkExec1(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *Attr, pipe int) (r1 uintptr, err1 syscall.Errno, p [2]int, locked bool) {
	var (
		state   childState
		nextfd  int
		i       int
		cstatus childStatus
	)

	ppid, _, _ := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)

	fd := make([]int, len(attr.Files))
	nextfd = len(attr.Files)
	for i, ufd := range attr.Files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++

	runtime_BeforeFork()
	locked = true
	r1, _, err1 = syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD)|attr.Cloneflags, 0, 0, 0, 0, 0)
	if err1 != 0 || r1 != 0 {
		return
	}

	// In Child
	runtime_AfterForkInChild()

	if attr.Setpgid {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETPGID, 0, uintptr(attr.Pgid), 0)
		if err1 != 0 {
			state = childStateSetpgid
			goto childerror
		}
	}

	if chroot != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHROOT, uintptr(unsafe.Pointer(chroot)), 0, 0)
		if err1 != 0 {
			state = childStateChroot
			goto childerror
		}
	}

	if dir != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
		if err1 != 0 {
			state = childStateChdir
			goto childerror
		}
	}

	if attr.Pdeathsig != 0 {
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(attr.Pdeathsig), 0, 0, 0, 0)
		if err1 != 0 {
			state = childStatePdeathsig
			goto childerror
		}
	}

	r1, _, _ = syscall.RawSyscall(syscall.SYS_GETPPID, 0, 0, 0)
	if r1 != ppid {
		pid, _, _ := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
		_, _, err1 := syscall.RawSyscall(syscall.SYS_KILL, pid, uintptr(attr.Pdeathsig), 0)
		if err1 != 0 {
			// parent is dead so no need to set state
			goto childerror
		}
	}

	if attr.SetNoNewPrivs {
		err1 = asm_prctl_set_no_new_privs()
		if err1 != 0 {
			state = childStateNoNewPrivs
			goto childerror
		}
	}

	if pipe < nextfd {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP, uintptr(pipe), uintptr(nextfd), 0)
		if err1 != 0 {
			state = childStateDup
			goto childerror
		}
		syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
		pipe = nextfd
		nextfd++
	}

	for i = 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < int(i) {
			if nextfd == pipe {
				nextfd++
			}
			_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP, uintptr(fd[i]), uintptr(nextfd), 0)
			if err1 != 0 {
				state = childStateDup
				goto childerror
			}
			syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
			fd[i] = nextfd
			nextfd++
		}
	}

	for i = 0; i < len(fd); i++ {
		if fd[i] == -1 {
			syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == int(i) {
			_, _, err1 = syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd[i]), syscall.F_SETFD, 0)
			if err1 != 0 {
				state = childStateClearCloexec
				goto childerror
			}
			continue
		}

		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			state = childStateDup
			goto childerror
		}
	}

	for i = len(fd); i < 3; i++ {
		syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(i), 0, 0)
	}

	if attr.Seccomp != nil {
		err1 = asm_seccomp(attr.SeccompFlags, attr.buf[:], attr.Seccomp)
		if err1 != 0 {
			state = childStateSeccomp
			goto childerror
		}
	}

	// Time to exec.
	_, _, err1 = syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])))
	state = childStateExec

childerror:
	cstatus.state = state
	cstatus.errno = err1
	syscall.RawSyscall(syscall.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&cstatus)), unsafe.Sizeof(cstatus))
	for {
		syscall.RawSyscall(syscall.SYS_EXIT, 253, 0, 0)
	}
}
