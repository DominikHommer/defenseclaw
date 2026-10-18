// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
)

// HostStage is an owned, private sanitized project artifact on the trusted
// host. It contains no guest paths, runtime admission or launch authority.
// Its paths and summary are host-confidential and must not enter guest plans.
// Close must run after the owning adapter has finished reading the artifact.
type HostStage struct {
	mu       sync.Mutex
	record   CopyRecord
	identity string
	closed   bool
	close    func() error
	closeErr error
}

// HostStageSummary describes host staging only. It is not a persisted copy
// record: a qualified provider must separately bind the guest layout and
// workspace operations before importing this tree.
type HostStageSummary struct {
	Project, SourceIdentity string
	Kind                    CopyKind
	Head, Baseline          string
	Files                   int
	Bytes                   int64
	HeldBack, Unmasked      []string
	Warnings                []string
	Remotes, LineEndings    map[string]string
}

func (s *HostStage) Summary() HostStageSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.record
	return HostStageSummary{
		Project: r.Project, SourceIdentity: s.identity, Kind: r.Kind,
		Head: r.Head, Baseline: r.Baseline, Files: r.Files, Bytes: r.Bytes,
		HeldBack: slices.Clone(r.HeldBack), Unmasked: slices.Clone(r.Unmasked),
		Warnings: slices.Clone(r.Warnings), Remotes: maps.Clone(r.Remotes), LineEndings: maps.Clone(r.LineEndings),
	}
}

// TreePath returns the sanitized host tree while its owner retains custody.
// It is never a guest workspace path or permission to mount the original tree.
func (s *HostStage) TreePath() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", errors.New("workspace: host stage is closed")
	}
	return s.record.Stage, nil
}

// Close removes only this artifact's private owned root. A bounded cleanup
// refusal is returned to the owner, which must retain/report the residue.
func (s *HostStage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.closeErr = s.close()
	}
	return s.closeErr
}

// PrepareHostStage captures and sanitizes a host project without enabling any
// guest operations. The initial supported floor is Windows on a genuine local
// fixed NTFS mount, private current-user staging, no reparse points, named
// streams, hardlinks, case-sensitive directories or ambiguous Windows names.
// Linked/external git metadata is refused. Stage and live-mount support are
// unchanged; native Windows requires separate typed guest-operation tests.
// MaxBytes also bounds the initial complete source capture, including git
// metadata and files that the later sanitizer would ignore or hold back.
func PrepareHostStage(ctx context.Context, opts StageOptions) (*HostStage, error) {
	if err := ValidateName(opts.Name); err != nil {
		return nil, err
	}
	if opts.RemoteRoot != "" {
		return nil, errors.New("workspace: host staging accepts no guest remote root")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return prepareHostStagePlatform(ctx, opts)
}
