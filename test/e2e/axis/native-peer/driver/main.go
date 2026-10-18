// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor outer custody. No production runtime or arbitrary launcher.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
	"runtime"
	"time"
)

const outputLimit = 64 << 10
const scope = "fixed_linux_native_peer_outer_driver_v1"
const receiptSHA = "9e7c6f82be689db0167067b0eb108f48870279e4a015c1b91604583b063e02db"

var errUnreviewed = errors.New("fixed wrapper artifact has no reviewed driver admission")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type wrapperAdmission struct {
	Reviewed bool
	SHA      string
	Size     int64
}

// Source, Actions/archive/provenance and static image independently reviewed by
// two reviewers. This admits only the fixed contributor wrapper as an input;
// the driver needs its own build/image review before any run. No CLI/env override.
var liveAdmission = wrapperAdmission{Reviewed: true,
	SHA:  "4b64f27003027663af8bce1c2159daa9f8315635a6e3b5504f345178e9750455",
	Size: 3440766,
}

func (a wrapperAdmission) validate() error {
	if !a.Reviewed || !digestPattern.MatchString(a.SHA) || a.Size < 64 || a.Size > 32<<20 {
		return errUnreviewed
	}
	return nil
}

type options struct{ receipt, evidence string }
type driverRun func(context.Context, options, wrapperAdmission, map[string]any, *cleanupOwner) error

func digestBytes(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func execute(args []string, admission wrapperAdmission, run driverRun) (map[string]any, *cleanupOwner, error) {
	record := map[string]any{"scope": scope, "passed": false, "execution_performed": false, "production_certification": false}
	owner := &cleanupOwner{}
	// Before metadata paths, filesystem reads, memfds or any native launch.
	if err := admission.validate(); err != nil {
		return record, owner, err
	}
	flags := flag.NewFlagSet("fixed-native-outer-driver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	explicit := flags.Bool("run-fixed", false, "explicit reviewed fixed contributor experiment")
	var opts options
	flags.StringVar(&opts.receipt, "receipt", "", "fixed reviewed artifact metadata")
	flags.StringVar(&opts.evidence, "evidence", "", "fresh private wrapper evidence metadata")
	if flags.Parse(args) != nil || !*explicit || flags.NArg() != 0 || opts.receipt == "" || opts.evidence == "" || len(opts.receipt) > 4096 || len(opts.evidence) > 4096 || run == nil {
		return record, owner, errors.New("fixed contributor selector and bounded metadata required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return record, owner, run(ctx, opts, admission, record, owner)
}

func main() {
	var record map[string]any
	var owner *cleanupOwner
	var err error
	if len(os.Args) > 1 && os.Args[1] == "--owned-wrapper-bootstrap" {
		record, owner, err = bootstrap(os.Args[2:], liveAdmission)
	} else {
		record, owner, err = execute(os.Args[1:], liveAdmission, runDriver)
	}
	if err != nil {
		record["error"] = "fixed_outer_driver_admission_or_observation_failed"
		record["passed"] = false
	}
	writeErr := json.NewEncoder(os.Stdout).Encode(record)
	runtime.KeepAlive(owner)
	if writeErr != nil || err != nil {
		os.Exit(1)
	}
}
