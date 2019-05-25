// +build !arm64

package forkexec

import "syscall"

const _SYS_dup = syscall.SYS_DUP2
