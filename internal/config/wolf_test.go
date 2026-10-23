// SPDX-License-Identifier: Apache-2.0
package config

import "testing"

func TestWolfConfigDefaultsAndValidation(t *testing.T) {
	w := DefaultWolfConfig()
	if w.Enabled || w.Variant != "small" || w.Threshold != .5 || w.TimeoutMs != 500 {
		t.Fatalf("unexpected defaults: %+v", w)
	}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	w.Enabled = true
	if w.Validate() == nil {
		t.Fatal("missing paths accepted")
	}
	w.ModelDir = "/models/wolf"
	w.PythonExecutable = "/runtime/bin/python"
	for _, v := range []string{"small", "full"} {
		w.Variant = v
		if err := w.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	w.Variant = "other"
	if w.Validate() == nil {
		t.Fatal("invalid variant accepted")
	}
	w.Variant = "small"
	w.OverlapTokens = w.WindowTokens
	if w.Validate() == nil {
		t.Fatal("invalid overlap accepted")
	}
}
