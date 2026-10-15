// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestNilCommandRedirectFacts(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		access        PathAccess
		path          string
	}{
		{"output then delete", ">scratch; rm -rf /", PathAccessDelete, "/"},
		{"append then delete", ">>scratch; rm -rf /", PathAccessDelete, "/"},
		{"output then read", ">scratch; cat ~/.ssh/id_rsa", PathAccessRead, "/home/dev/.ssh/id_rsa"},
		{"append then read", ">>scratch; cat ~/.ssh/id_rsa", PathAccessRead, "/home/dev/.ssh/id_rsa"},
		{"output then alert", ">scratch; cat ~/.aws/credentials", PathAccessRead, "/home/dev/.aws/credentials"},
		{"append then alert", ">>scratch; cat ~/.aws/credentials", PathAccessRead, "/home/dev/.aws/credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: tc.command, CWD: "/work", ActiveHome: "/home/dev", DialectHint: DialectPOSIX})
			projection := facts.EnforcementProjection()
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				!projection.EnforcementEligible() || len(facts.Commands) != 2 {
				t.Fatalf("facts parse=%+v commands=%+v, want two eligible commands", facts.Parse, facts.Commands)
			}
			first := facts.Commands[0]
			if first.Kind != CommandKindShellRedirect || first.Effect != EffectExecute ||
				first.Executable != "" || len(first.Redirects) != 1 || first.Redirects[0].Target != "scratch" {
				t.Fatalf("first command=%+v, want static shell redirect", first)
			}
			found := false
			for _, path := range projection.Paths {
				if path.Access == tc.access && path.Resolved == tc.path {
					found = true
				}
			}
			if !found {
				t.Fatalf("enforcement paths=%+v, want %s %s", projection.Paths, tc.access, tc.path)
			}
		})
	}
}

func TestNilCommandRedirectRetainsTarget(t *testing.T) {
	facts := Analyze(Input{
		Tool: "shell", Command: ">>/home/dev/.ssh/authorized_keys; echo done",
		CWD: "/work", ActiveHome: "/home/dev", DialectHint: DialectPOSIX,
	})
	if !facts.EnforcementEligible() {
		t.Fatalf("facts parse=%+v commands=%+v, want eligible", facts.Parse, facts.Commands)
	}
	for _, path := range facts.EnforcementProjection().Paths {
		if path.CommandID == facts.Commands[0].ID && path.Access == PathAccessAppend &&
			path.Resolved == "/home/dev/.ssh/authorized_keys" {
			return
		}
	}
	t.Fatalf("redirect path missing from enforcement projection: %+v", facts.EnforcementProjection().Paths)
}

func TestNilCommandRedirectKeepsUnknownFormsPartial(t *testing.T) {
	for _, command := range []string{
		">$TARGET; rm -rf /",
		"1>&2; rm -rf /",
		"HOME=/tmp; cat ~/.ssh/id_rsa",
		"true; cat ~/.ssh/id_rsa",
	} {
		t.Run(command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: command, CWD: "/work", ActiveHome: "/home/dev", DialectHint: DialectPOSIX})
			if facts.Authoritative() || facts.EnforcementEligible() {
				t.Fatalf("facts parse=%+v commands=%+v, want partial", facts.Parse, facts.Commands)
			}
		})
	}
}

func TestNilCommandRedirectQuotedHeredoc(t *testing.T) {
	for _, command := range []string{
		"<<'EOF'\nbody\nEOF\nrm -rf /",
		">scratch <<'EOF'\nbody\nEOF\nrm -rf /",
		"<<'EOF'\nbody\nEOF\ncat ~/.ssh/id_rsa",
		">scratch <<'EOF'\nbody\nEOF\ncat ~/.ssh/id_rsa",
	} {
		t.Run(command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: command, CWD: "/work", ActiveHome: "/home/dev", DialectHint: DialectPOSIX})
			if !facts.Authoritative() || !facts.EnforcementProjection().EnforcementEligible() {
				t.Fatalf("facts parse=%+v commands=%+v, want eligible", facts.Parse, facts.Commands)
			}
			if len(facts.Commands) == 0 || facts.Commands[len(facts.Commands)-1].Effect != EffectExecute {
				t.Fatalf("commands=%+v, want an executable final command", facts.Commands)
			}
		})
	}
}
