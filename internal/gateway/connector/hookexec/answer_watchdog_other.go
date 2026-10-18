// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"sync"
	"time"
)

// answerDeadlineWaiter waits for a tool call's answer deadline unless it is
// cancelled first.
type answerDeadlineWaiter struct {
	once sync.Once
	done chan struct{}
}

func newAnswerDeadlineWaiter() *answerDeadlineWaiter {
	return &answerDeadlineWaiter{done: make(chan struct{})}
}

func (w *answerDeadlineWaiter) cancel() { w.once.Do(func() { close(w.done) }) }

// wait reports whether deadline came before a cancel.
func (w *answerDeadlineWaiter) wait(deadline time.Time) bool {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-w.done:
		return false
	case <-timer.C:
	}
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}
