//go:build unix

package cliagent

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func platformSupported() error { return nil }

// configureProcessGroup starts the child in its own process group. On context
// cancellation the whole group gets SIGTERM; after grace, Wait stops waiting,
// kills the leader and closes the pipes.
func configureProcessGroup(cmd *exec.Cmd, grace time.Duration) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = grace
}

// killProcessGroup SIGKILLs anything left in the child's group after Wait, so
// descendants cannot outlive the call.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
