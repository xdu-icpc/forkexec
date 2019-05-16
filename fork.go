package forkexec

func ForkExec(argv0 string, argv []string, attr *Attr) (pid int, err error) {
	return forkExec(argv0, argv, attr)
}
