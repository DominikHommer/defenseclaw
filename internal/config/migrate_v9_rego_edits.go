// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
	"github.com/defenseclaw/defenseclaw/internal/policy/regodata"
)

// legacy08Rego holds every version of the vendor Rego modules 0.5.0 to
// 0.8.10 seeded (<module>-<first release>.rego): admission changed in 0.8.0,
// guardrail and skill_actions never did. The migration compares the copy of
// an operator with them to find the rules the operator added
// (v9CarryRegoEdits, GAP-1498). Remove with the v8 to v9 migration (1.1.0).
//
//go:embed legacy08rego/*.rego
var legacy08Rego embed.FS

// v9CarriedRegoReads are the data documents of the 0.8.x admission module
// whose values the 1.0 admission module reads from input.admission in the
// same shape. Other documents moved to another shape or are gone, so a rule
// that reads them cannot be carried.
var v9CarriedRegoReads = []struct {
	from *regexp.Regexp
	to   string
}{
	{regexp.MustCompile(`\bdata\.config\.allow_list_bypass_scan\b`), "input.admission.allow_list_bypass_scan"},
	{regexp.MustCompile(`\bdata\.config\.scan_on_install\b`), "input.admission.scan_on_install"},
	{regexp.MustCompile(`\bdata\.actions\b`), "input.admission.actions"},
}

// v9RegoEdits is what an operator changed in a 0.8.x vendor module.
type v9RegoEdits struct {
	// module is the custom module with the rules the operator added, its
	// data reads moved to input (nil when nothing can or needs carrying).
	module []byte
	// rules names the added rules.
	rules []string
	// lost says why the edits cannot be carried ("" when they can, or for
	// an unedited copy).
	lost string
}

// v9CarryRegoEdits compares edited, the operator copy of the vendor module
// name, with the copies 0.5.0 to 0.8.10 seeded. 1.0 replaces a pre-9 vendor
// module with the shipped one, which dropped the decisions an operator had
// added, such as a block on a named skill (GAP-1498). The rules added to an
// otherwise unchanged copy are carried to a custom module in the same
// package that reads the same values from input, provided it compiles with
// the shipped module and reads no data document 1.0 no longer provides. A
// copy whose 0.8.x rules were changed or removed, or whose added rules cannot
// be carried, is reported instead (lost).
func v9CarryRegoEdits(name string, edited *ast.Module, shipped []byte) v9RegoEdits {
	added, ok := v9AddedRegoRules(name, edited)
	switch {
	case !ok:
		return v9RegoEdits{lost: "it changes or removes rules of the 0.8.x module"}
	case len(added) == 0:
		return v9RegoEdits{}
	case shipped == nil:
		return v9RegoEdits{lost: "1.0 no longer ships or reads this module"}
	}
	var original, carried strings.Builder
	header := "# The rules you added to the 0.8.x " + name + ", kept by the 1.0 upgrade. They read\n" +
		"# input.admission where the 0.8.x module read data.json.\n" + edited.Package.String() + "\n\nimport rego.v1\n"
	original.WriteString(header)
	carried.WriteString(header)
	var rules []string
	for _, rule := range added {
		text := string(rule.Location.Text)
		original.WriteString("\n" + text + "\n")
		for _, read := range v9CarriedRegoReads {
			text = read.from.ReplaceAllString(text, read.to)
		}
		carried.WriteString("\n" + text + "\n")
		rules = append(rules, rule.Head.Ref().String())
	}
	const notCopied = "its added rules could not be copied"
	// The rule texts must parse back to the rules they came from.
	parsedOriginal, err := v9ParseRego(name, original.String())
	if err != nil || len(parsedOriginal.Rules) != len(added) {
		return v9RegoEdits{rules: rules, lost: notCopied}
	}
	for i, rule := range parsedOriginal.Rules {
		if !rule.Equal(added[i]) {
			return v9RegoEdits{rules: rules, lost: notCopied}
		}
	}
	module, err := v9ParseRego(name, carried.String())
	if err != nil {
		return v9RegoEdits{rules: rules, lost: notCopied}
	}
	if _, docs := regodata.ModuleReads(module); len(docs) > 0 {
		return v9RegoEdits{rules: rules, lost: "its added rules read " + strings.Join(docs, ", ") +
			", which 1.0 no longer provides"}
	}
	shippedModule, err := v9ParseRego(name, string(shipped))
	if err != nil {
		return v9RegoEdits{rules: rules, lost: "the shipped module could not be read"}
	}
	compiler := ast.NewCompiler()
	if compiler.Compile(map[string]*ast.Module{name: shippedModule, "carried-" + name: module}); compiler.Failed() {
		return v9RegoEdits{rules: rules, lost: fmt.Sprintf("its added rules do not compile with the 1.0 module (%v)",
			compiler.Errors[0].Message)}
	}
	return v9RegoEdits{module: []byte(carried.String()), rules: rules}
}

// v9AddedRegoRules returns the rules of edited that are not in the 0.8.x
// copy of name it otherwise matches (rules compare without their layout and
// comments). ok is false when no copy has all its rules in edited, or when
// edited adds an import or names another package.
func v9AddedRegoRules(name string, edited *ast.Module) (added []*ast.Rule, ok bool) {
	stem := strings.TrimSuffix(name, ".rego")
	entries, err := fs.ReadDir(legacy08Rego, "legacy08rego")
	if err != nil {
		return nil, false
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), stem+"-") {
			continue
		}
		raw, err := legacy08Rego.ReadFile(path.Join("legacy08rego", entry.Name()))
		if err != nil {
			continue
		}
		pristine, err := v9ParseRego(name, string(raw))
		if err != nil || !pristine.Package.Equal(edited.Package) || !v9ImportsWithin(edited, pristine) {
			continue
		}
		used := make([]bool, len(edited.Rules))
		matched := true
		for _, rule := range pristine.Rules {
			found := false
			for i, candidate := range edited.Rules {
				if !used[i] && candidate.Equal(rule) {
					used[i], found = true, true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		var extra []*ast.Rule
		for i, rule := range edited.Rules {
			if !used[i] {
				extra = append(extra, rule)
			}
		}
		if !ok || len(extra) < len(added) {
			added, ok = extra, true
		}
	}
	return added, ok
}

func v9ImportsWithin(edited, pristine *ast.Module) bool {
	for _, imp := range edited.Imports {
		found := false
		for _, other := range pristine.Imports {
			if imp.Equal(other) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func v9ParseRego(name, text string) (*ast.Module, error) {
	return ast.ParseModuleWithOpts(name, text, ast.ParserOptions{RegoVersion: ast.RegoV1})
}

// v9CarriedRegoPath is where the custom module with the rules carried from
// the vendor module at modulePath goes: custom-<module>-from-0.8.rego beside
// it (a name upgrades never touch), or a free numbered name. A file that
// already holds data is reused, so a retry writes no second copy.
func v9CarriedRegoPath(modulePath string, data []byte) string {
	stem := strings.TrimSuffix(filepath.Base(modulePath), ".rego")
	base := filepath.Join(filepath.Dir(modulePath), "custom-"+stem+"-from-0.8")
	candidate := base + ".rego"
	for n := 2; ; n++ {
		existing, err := os.ReadFile(candidate)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && bytes.Equal(existing, data)) {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d.rego", base, n)
	}
}

// writeV9CarriedRego writes the carried module of refresh unless the file
// already holds it.
func writeV9CarriedRego(refresh v9RegoRefresh, mode fs.FileMode) error {
	if refresh.carried == nil {
		return nil
	}
	if existing, err := os.ReadFile(refresh.carriedPath); err == nil && bytes.Equal(existing, refresh.carried) {
		return nil
	}
	return cfgtxn.WriteFileDurable(refresh.carriedPath, refresh.carried, mode)
}
