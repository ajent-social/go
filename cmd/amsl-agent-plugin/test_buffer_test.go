package main

import (
	"bytes"
	"sync"
)

// Subprocess stderr is written by os/exec while protocol assertions read it.
// Expose only synchronized methods; embedding bytes.Buffer would leak ReadFrom.
type synchronizedTestBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedTestBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *synchronizedTestBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
