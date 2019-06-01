package forkexec

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"
	"unsafe"

	"github.com/xdu-icpc/seccomp"
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
	childStateClosePipe
	childStateReadPipeForIdMapping
	childStateConfirmIdMapping
	childStateSetsid
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
	"can not close pipe",
	"can not read pipe for ID mapping",
	"fail to set ID mapping",
	"setsid",
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

	fprog, err := seccomp.NewSockFprog(attr.Seccomp)
	if err != nil {
		return 0, err
	}

	syscall.ForkLock.Lock()
	err = syscall.Pipe2(p[:], syscall.O_CLOEXEC)
	if err != nil {
		syscall.ForkLock.Unlock()
		return 0, err
	}

	pid, err1 = doForkExec(argv0p, argvp, envvp, chroot, dir, attr, p[1], fprog)
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
func doForkExec(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *Attr, pipe int, fprog *seccomp.SockFprog) (pid int, err syscall.Errno) {
	r1, err1, p, locked := doForkExec1(argv0, argv, envv, chroot, dir, attr, pipe, fprog)
	if locked {
		runtime_AfterFork()
	}
	if err1 != 0 {
		return 0, err1
	}

	pid = int(r1)

	if attr.UidMappings != nil || attr.GidMappings != nil {
		syscall.Close(p[0])
		err := writeUidGidMappings(pid, attr)
		var err2 syscall.Errno
		if err != nil {
			err2 = err.(syscall.Errno)
		}
		syscall.RawSyscall(syscall.SYS_WRITE, uintptr(p[1]), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
		syscall.Close(p[1])
	}

	return pid, 0
}

//go:noinline
//go:norace
func doForkExec1(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *Attr, pipe int, fprog *seccomp.SockFprog) (r1 uintptr, err1 syscall.Errno, p [2]int, locked bool) {
	var (
		state   childState
		nextfd  int
		i       int
		err2    syscall.Errno
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

	if attr.UidMappings != nil || attr.GidMappings != nil {
		if err2 := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err2 != nil {
			err1 = err2.(syscall.Errno)
			return
		}
	}

	runtime_BeforeFork()
	locked = true
	r1, _, err1 = syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD)|attr.Cloneflags, 0, 0, 0, 0, 0)
	if err1 != 0 || r1 != 0 {
		return
	}

	// In Child
	runtime_AfterForkInChild()

	// Wait for UID/GID mappings to be written.
	if attr.UidMappings != nil || attr.GidMappings != nil {
		if _, _, err1 = syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(p[1]), 0, 0); err1 != 0 {
			state = childStateClosePipe
			goto childerror
		}
		r1, _, err1 = syscall.RawSyscall(syscall.SYS_READ, uintptr(p[0]), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
		if err1 != 0 {
			state = childStateReadPipeForIdMapping
			goto childerror
		}
		if r1 != unsafe.Sizeof(err2) {
			err1 = syscall.EINVAL
			state = childStateReadPipeForIdMapping
			goto childerror
		}
		if err2 != 0 {
			err1 = err2
			state = childStateConfirmIdMapping
			goto childerror
		}
	}

	if attr.Setsid {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
		if err1 != 0 {
			state = childStateSetsid
			goto childerror
		}
	}

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
		_, _, err1 = syscall.RawSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0)
		if err1 != 0 {
			state = childStateNoNewPrivs
			goto childerror
		}
	}

	if pipe < nextfd {
		_, _, err1 = syscall.RawSyscall(_SYS_dup, uintptr(pipe), uintptr(nextfd), 0)
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
			_, _, err1 = syscall.RawSyscall(_SYS_dup, uintptr(fd[i]), uintptr(nextfd), 0)
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

		_, _, err1 = syscall.RawSyscall(_SYS_dup, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			state = childStateDup
			goto childerror
		}
	}

	for i = len(fd); i < 3; i++ {
		syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(i), 0, 0)
	}

	if fprog != nil {
		_, _, err1 = syscall.RawSyscall(unix.SYS_SECCOMP, 1, attr.SeccompFlags, uintptr(unsafe.Pointer(fprog)))
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

func writeUidGidMappings(pid int, attr *Attr) error {
	if attr.UidMappings != nil {
		fn := fmt.Sprintf("/proc/%d/uid_map", pid)
		if err := writeIDMappings(fn, attr.UidMappings); err != nil {
			return err
		}
	}

	if attr.GidMappings != nil {
		if err := writeSetgroups(pid, attr.GidMappingsEnableSetgroups); err != nil && err != syscall.ENOENT {
			return err
		}
		fn := fmt.Sprintf("/proc/%d/gid_map", pid)
		if err := writeIDMappings(fn, attr.GidMappings); err != nil {
			return err
		}
	}
	return nil
}

func writeSetgroups(pid int, enable bool) error {
	fn := fmt.Sprintf("/proc/%d/setgroups", pid)
	fd, err := syscall.Open(fn, syscall.O_RDWR, 0)
	if err != nil {
		return err
	}

	var data []byte
	if enable {
		data = []byte("allow")
	} else {
		data = []byte("deny")
	}

	if _, err = syscall.Write(fd, data); err != nil {
		syscall.Close(fd)
		return err
	}

	return syscall.Close(fd)
}

func writeIDMappings(path string, idMap []syscall.SysProcIDMap) error {
	fd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		return err
	}

	data := ""
	for _, im := range idMap {
		data = data + fmt.Sprintf("%d %d %d\n", im.ContainerID, im.HostID, im.Size)
	}

	bytes, err := syscall.ByteSliceFromString(data)
	if err != nil {
		syscall.Close(fd)
		return err
	}

	if _, err := syscall.Write(fd, bytes); err != nil {
		syscall.Close(fd)
		return err
	}

	return syscall.Close(fd)
}
