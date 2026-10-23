// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// Every rule is evaluated on each simple command with the same facts and
// disposition it gets when that command is submitted by itself.
func TestTrustedActionEverySimpleCommandMatchesStandalone(t *testing.T) {
	const connector = "all-simple-commands-test"
	installDefaultProfileConnector(t, connector)
	tests := []struct {
		name, command, alone, ruleID, cwd, aloneCWD string
	}{
		{"sequence", "cat ~/.ssh/id_rsa; echo done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"and list", "true && cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"or list", "false || cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"pipeline", "cat ~/.ssh/id_rsa | cat", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"group", "{ cat ~/.ssh/id_rsa; }", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"subshell", "(cat ~/.ssh/id_rsa)", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"redirected group", "{ cat ~/.ssh/id_rsa; } 2>/tmp/error", "cat ~/.ssh/id_rsa 2>/tmp/error", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"credential input on group", "{ cat; } < /home/alice/.ssh/id_rsa", "cat < /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"subshell in pipeline", "(cat ~/.ssh/id_rsa) | cat", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"negated", "! cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"background", "cat ~/.ssh/id_rsa & echo done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"if body", "if true; then cat ~/.ssh/id_rsa; fi", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"if body changes later directory", "if true; then cd /home/alice; fi; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/repo", "/home/alice"},
		{"loop body changes later directory", "for i in 1; do cd /home/alice; done; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/repo", "/home/alice"},
		{"while body", "while true; do cat ~/.ssh/id_rsa; done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"for body", "for i in 1; do cat ~/.ssh/id_rsa; done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"case body", "case x in x) cat ~/.ssh/id_rsa;; esac", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"env prefix", "X=1 cat ~/.ssh/id_rsa; echo done", "X=1 cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"env prefix under redirected group", "{ X=1 cat ~/.ssh/id_rsa; } 2>/tmp/error", "X=1 cat ~/.ssh/id_rsa 2>/tmp/error", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"own redirect", "cat ~/.ssh/id_rsa 2>/tmp/error; echo done", "cat ~/.ssh/id_rsa 2>/tmp/error", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"bare assignment", "X=1; cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"resolution assignment", "PATH=/tmp; cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"home assignment retains identity", "HOME=/tmp; cat /home/alice/.ssh/id_rsa", "cat /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"static cd", "cd /home/alice && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"failed cd keeps old directory", "cd /does/not/exist/defenseclaw; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice", ""},
		{"cd back", "cd /tmp; cd -; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice", ""},
		{"home cd", "cd \"$HOME\" && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"tilde cd", "cd ~ && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"assigned cd", "DIR=/home/alice; cd \"$DIR\" && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"pwd cd", "cd \"$PWD/..\" && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"pwd after cd", "cd /home/alice && cat \"$PWD/.ssh/id_rsa\"", "cat /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"assigned path", "KEY=/home/alice/.ssh/id_rsa; cat \"$KEY\"", "cat /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"sqlite sequence", "sqlite3 app.db '.shell /bin/sh'; echo done", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite and list", "true && sqlite3 app.db '.shell /bin/sh'", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite pipeline", "sqlite3 app.db '.shell /bin/sh' | cat", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite subshell", "(sqlite3 app.db '.shell /bin/sh')", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite redirected group", "{ sqlite3 app.db '.shell /bin/sh'; } 2>/tmp/error", "sqlite3 app.db '.shell /bin/sh' 2>/tmp/error", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite env prefix", "X=1 sqlite3 app.db '.shell /bin/sh'; true", "X=1 sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"mysql or list", "mysql --database=app --execute='\\! /bin/bash' || true", "mysql --database=app --execute='\\! /bin/bash'", "exec.mysql_client_shell_escape", "/repo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := func(command, cwd string) *RuleFinding {
				request := trustedActionRequest{
					Input: actionfacts.Input{Tool: "shell", Command: command, CWD: cwd,
						ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
					LegacyText: command, Connector: connector, EnforcementCapable: true,
				}
				return findingWithID(dispatchTrustedAction(t.Context(), request), tt.ruleID)
			}
			aloneCWD := tt.aloneCWD
			if aloneCWD == "" {
				aloneCWD = tt.cwd
			}
			alone := check(tt.alone, aloneCWD)
			got := check(tt.command, tt.cwd)
			if alone == nil {
				t.Fatalf("%s: standalone rule did not match", tt.ruleID)
			}
			if got == nil || got.contributesToEnforcement() != alone.contributesToEnforcement() ||
				got.contributesToAlertOnly() != alone.contributesToAlertOnly() {
				t.Errorf("%q: %s finding=%+v, standalone=%+v", tt.command, tt.ruleID, got, alone)
			}
		})
	}
}

// GAP-0789: an unrelated command before or after a read cannot remove the
// read-path rule's standalone disposition. Some reads are advisory by policy;
// those must keep the same disposition as the standalone read too.
func TestTrustedActionReadPathsInEveryListPosition(t *testing.T) {
	const connector = "read-path-list-position-test"
	installDefaultProfileConnector(t, connector)
	reads := []struct {
		name, ruleID, command string
		noStandaloneFinding   bool
	}{
		{name: "SSH private key", ruleID: "PATH-SSH-KEY", command: "cat /home/alice/.ssh/id_rsa"},
		{name: "AWS credentials", ruleID: "PATH-AWS-CREDS", command: "cat /home/alice/.aws/credentials"},
		{name: "AWS config", ruleID: "PATH-AWS-CONFIG", command: "cat /home/alice/.aws/config"},
		{name: "password-cracker potfile", ruleID: "PATH-PASSWORD-CRACKER-POTFILE", command: "cat /home/alice/.john/john.pot"},
		{name: "Kubernetes config", ruleID: "PATH-KUBE", command: "cat /home/alice/.kube/config"},
		{name: "Docker config", ruleID: "PATH-DOCKER", command: "cat /home/alice/.docker/config.json"},
		{name: "GnuPG keyring", ruleID: "PATH-GNUPG", command: "cat /home/alice/.gnupg/secring.gpg"},
		{name: "npmrc alias", ruleID: "PATH-DOCKER", command: "cat /home/alice/.npmrc"},
		{name: "pypirc alias", ruleID: "PATH-DOCKER", command: "cat /home/alice/.pypirc"},
		{name: "Git credentials", ruleID: "PATH-GIT-CREDS", command: "cat /home/alice/.git-credentials"},
		{name: "netrc alias", ruleID: "PATH-GIT-CREDS", command: "cat /home/alice/.netrc"},
		{name: "environment file", ruleID: "PATH-ENV-FILE", command: "cat /home/alice/project/.env", noStandaloneFinding: true},
		{name: "passwd", ruleID: "PATH-ETC-PASSWD", command: "cat /etc/passwd", noStandaloneFinding: true},
		{name: "sudoers", ruleID: "PATH-ETC-SUDOERS", command: "cat /etc/sudoers", noStandaloneFinding: true},
		{name: "shadow", ruleID: "PATH-ETC-SHADOW", command: "cat /etc/shadow"},
		{name: "proc environ", ruleID: "PATH-PROC-ENVIRON", command: "cat /proc/self/environ"},
		{name: "cloud credentials", ruleID: "secrets.cloud_credential_read", command: "cat /home/alice/.config/gcloud/application_default_credentials.json"},
		{name: "browser sessions", ruleID: "secrets.browser_session_store_read", command: "cat '/home/alice/.config/google-chrome/Default/Login Data'"},
		{name: "workload token", ruleID: "secrets.workload_identity_token_read", command: "cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
	}
	forms := []struct {
		name, first, last, middle string
	}{
		{"sequence", "%s; true", "true; %s", "true; %s; true"},
		{"and list", "%s && true", "true && %s", "true && %s && true"},
		{"or list", "%s || true", "false || %s", "false || %s || true"},
		{"pipeline", "%s | cat", "true | %s", "true | %s | cat"},
		{"newline", "%s\ntrue", "true\n%s", "true\n%s\ntrue"},
	}
	check := func(command string) []RuleFinding {
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
	}
	for _, read := range reads {
		t.Run(read.name, func(t *testing.T) {
			aloneFindings := check(read.command)
			alone := findingWithID(aloneFindings, read.ruleID)
			if (alone == nil) != read.noStandaloneFinding {
				t.Fatalf("%s: standalone %s finding=%+v, all=%v", read.command, read.ruleID,
					alone, FindingStrings(aloneFindings))
			}
			for _, form := range forms {
				for position, format := range map[string]string{
					"first": form.first, "last": form.last, "middle": form.middle,
				} {
					t.Run(form.name+"/"+position, func(t *testing.T) {
						command := fmt.Sprintf(format, read.command)
						got := findingWithID(check(command), read.ruleID)
						if (got == nil) != (alone == nil) || got != nil &&
							(got.contributesToEnforcement() != alone.contributesToEnforcement() ||
								got.contributesToAlertOnly() != alone.contributesToAlertOnly()) {
							t.Errorf("%q: %s finding=%+v, standalone=%+v", command, read.ruleID, got, alone)
						}
					})
				}
			}
		})
	}
}

func TestTrustedActionResolutionPrefixMatchesStandaloneInList(t *testing.T) {
	const connector = "compound-resolution-prefix-test"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	standalone := "PATH=/definitely/missing $'rm' -rf /"
	for _, command := range []string{
		standalone,
		standalone + "; true",
		"true && " + standalone,
		"false || " + standalone,
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: "/repo",
				DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		if finding := findingWithID(findings, "CMD-RM-RF"); finding != nil {
			t.Errorf("%q invented an executable rm: %+v", command, *finding)
		}
	}
}

func TestTrustedActionCompoundEvaluationLimitBlocks(t *testing.T) {
	const connector = "compound-limit-test"
	installDefaultProfileConnector(t, connector)
	command := strings.Repeat("true; ", 128) + "rm -rf /"
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	limit := findingWithID(findings, "ACTION-COMPOUND-LIMIT")
	if limit == nil || !limit.contributesToEnforcement() ||
		buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
		t.Fatalf("over-limit action was not blocked: %v", FindingStrings(findings))
	}
}

func TestTrustedActionRecursiveFunctionFailsClosed(t *testing.T) {
	const connector = "compound-recursion-test"
	installDefaultProfileConnector(t, connector)
	command := "f() { f; }; f"
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	if finding := findingWithID(findings, "ACTION-COMPOUND-UNPROVEN"); finding == nil || !finding.contributesToEnforcement() ||
		buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
		t.Fatalf("recursive function was not blocked: %v", FindingStrings(findings))
	}
}
