// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/test/e2e/axis/native-hook-canary/fixture"
	"golang.org/x/sys/unix"
)

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (out *boundedOutput) Write(raw []byte) (int, error) {
	if len(raw) > (16<<10)-out.Len() {
		out.overflow = true
		return 0, errors.New("fixed hook output bound")
	}
	return out.Buffer.Write(raw)
}

func loadProfile() (*hookexec.NativeSandboxProfile, error) {
	fd, err := unix.Open(hookexec.NativeSandboxHookProfile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-mounted-runtime")
	defer file.Close()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 || info.Mode&0777 != 0400 || info.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("fixed profile custody differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, err
	}
	return hookexec.DecodeNativeSandboxProfile(raw)
}

func exchange(ctx context.Context, profile *hookexec.NativeSandboxProfile, value fixture.Case, phase byte, run func(context.Context, hookexec.Options) int) (fixture.Row, error) {
	raw, err := value.Payload(phase)
	if err != nil {
		return fixture.Row{}, err
	}
	var stdout, stderr boundedOutput
	code := run(ctx, hookexec.Options{Connector: value.Name, Event: value.Event, HookContractID: profile.HookContract, HookSurface: profile.HookSurface, NativeSandbox: profile,
		Stdin: bytes.NewReader(raw), Stdout: &stdout, Stderr: &stderr})
	if stdout.overflow || stderr.overflow {
		return fixture.Row{}, errors.New("fixed hook output exceeded bound")
	}
	return fixture.Row{Phase: string(phase), Code: code, Stdout: stdout.String(), Stderr: stderr.String()}, nil
}

func run(ctx context.Context, input io.Reader, output io.Writer, profile *hookexec.NativeSandboxProfile, value fixture.Case) error {
	if profile == nil || profile.Validate() != nil || profile.Connector != value.Name {
		return errors.New("fixed profile/schema differs")
	}
	encoder := json.NewEncoder(output)
	if err := encoder.Encode(fixture.Row{Phase: "ready"}); err != nil {
		return err
	}
	for _, phase := range []byte{'A', 'B', 'S', 'L'} {
		var command [1]byte
		if _, err := io.ReadFull(input, command[:]); err != nil || command[0] != phase {
			return errors.New("fixed phase order differs")
		}
		row := fixture.Row{Phase: string(phase)}
		if phase == 'S' {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		} else {
			var err error
			row, err = exchange(ctx, profile, value, phase, hookexec.Run)
			if err != nil {
				return err
			}
		}
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	var extra [1]byte
	if n, err := input.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("fixed trailing command differs")
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	value, err := fixture.Lookup(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	profile, err := loadProfile()
	if err != nil {
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Second)
	defer cancel()
	if run(ctx, os.Stdin, os.Stdout, profile, value) != nil {
		os.Exit(1)
	}
	// No hook input command, provider, executable or arbitrary endpoint runs.
	os.Exit(23)
}
