// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood bench branch only: never merged.
package audit

import (
	"database/sql"
	"os"
	"strconv"
	"time"
)

var gfloodNoPresync = os.Getenv("GFLOOD_NOPRESYNC") == "1"

func init() {
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_FRACTION")); err == nil {
		walCatchUpFraction = int64(n)
	}
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_CAP_MS")); err == nil {
		walCatchUpCap = time.Duration(n) * time.Millisecond
	}
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_HOLDMAX_MS")); err == nil {
		walCatchUpHoldMax = time.Duration(n) * time.Millisecond
	}
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_SETTLE")); err == nil {
		walSettleRounds = n
	}
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_SETTLED_MS")); err == nil {
		walSettledSync = time.Duration(n) * time.Millisecond
	}
}

// gfloodCheckpointNoSync is the bench-only data point: the checkpoint
// connection runs with synchronous=OFF, so a checkpoint never syncs.
func gfloodCheckpointNoSync(db *sql.DB) {
	if os.Getenv("GFLOOD_CKPT_NOSYNC") != "1" {
		return
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA synchronous=OFF"); err != nil {
		panic(err)
	}
}
