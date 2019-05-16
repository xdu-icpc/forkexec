package forkexec

import (
	_ "unsafe"
)

//go:linkname runtime_BeforeFork syscall.runtime_BeforeFork
func runtime_BeforeFork()

//go:linkname runtime_AfterFork syscall.runtime_AfterFork
func runtime_AfterFork()

//go:linkname runtime_AfterForkInChild syscall.runtime_AfterForkInChild
func runtime_AfterForkInChild()
