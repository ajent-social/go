//go:build !unix

package cliagent

import (
	"errors"
	"os/exec"
	"time"
)

func platformSupported() error {
	return errors.New("cliagent: running tools requires a Unix platform with process groups")
}

func configureProcessGroup(*exec.Cmd, time.Duration) {}

func killProcessGroup(*exec.Cmd) {}
