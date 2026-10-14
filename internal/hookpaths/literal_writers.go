// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type literalWriterKind uint8

const (
	literalWriterAlways literalWriterKind = iota
	literalWriterMode
	literalWriterFlags
	literalWriterNodeOpen
	literalWriterPerlOpen
	literalWriterDestinationDirectory
	literalWriterDirectory
	literalWriterFileOrDirectory
)

type literalWriterRule struct {
	callee      string
	pathArg     int
	pathKeyword string
	modeArg     int
	modeKeyword string
	kind        literalWriterKind
}

// The table holds path positions and write conditions for each interpreter.
// Module bindings are resolved before a call is looked up here.
var literalWriterRules = map[string][]literalWriterRule{
	"python": {
		{"logging.basicConfig", -1, "filename", -1, "", literalWriterAlways},
		{"logging.FileHandler", 0, "filename", -1, "", literalWriterAlways},
		{"logging.handlers.RotatingFileHandler", 0, "filename", -1, "", literalWriterAlways},
		{"logging.handlers.WatchedFileHandler", 0, "filename", -1, "", literalWriterAlways},
		{"open", 0, "file", 1, "mode", literalWriterMode},
		{"builtins.open", 0, "file", 1, "mode", literalWriterMode},
		{"__builtins__.open", 0, "file", 1, "mode", literalWriterMode},
		{"io.open", 0, "file", 1, "mode", literalWriterMode},
		{"io.FileIO", 0, "file", 1, "mode", literalWriterMode},
		{"os.open", 0, "path", 1, "flags", literalWriterFlags},
		{"shutil.copy", 1, "dst", -1, "", literalWriterDestinationDirectory},
		{"shutil.copy2", 1, "dst", -1, "", literalWriterDestinationDirectory},
		{"shutil.copyfile", 1, "dst", -1, "", literalWriterAlways},
		{"shutil.copyfileobj", 1, "fdst", -1, "", literalWriterAlways},
		{"shutil.copytree", 1, "dst", -1, "", literalWriterDirectory},
		{"shutil.move", 1, "dst", -1, "", literalWriterDestinationDirectory},
		{"os.rename", 1, "dst", -1, "", literalWriterAlways},
		{"os.replace", 1, "dst", -1, "", literalWriterAlways},
		{"os.truncate", 0, "path", -1, "", literalWriterAlways},
		{"pathlib.Path.open", 0, "", 0, "mode", literalWriterMode},
		{"pathlib.Path.write_text", 0, "", -1, "", literalWriterAlways},
		{"pathlib.Path.write_bytes", 0, "", -1, "", literalWriterAlways},
		{"pathlib.Path.touch", 0, "", -1, "", literalWriterAlways},
	},
	"node": {
		{"fs.writeFile", 0, "", -1, "", literalWriterAlways},
		{"fs.writeFileSync", 0, "", -1, "", literalWriterAlways},
		{"fs.appendFile", 0, "", -1, "", literalWriterAlways},
		{"fs.appendFileSync", 0, "", -1, "", literalWriterAlways},
		{"fs.copyFile", 1, "", -1, "", literalWriterAlways},
		{"fs.copyFileSync", 1, "", -1, "", literalWriterAlways},
		{"fs.cp", 1, "", -1, "", literalWriterFileOrDirectory},
		{"fs.cpSync", 1, "", -1, "", literalWriterFileOrDirectory},
		{"fs.rename", 1, "", -1, "", literalWriterAlways},
		{"fs.renameSync", 1, "", -1, "", literalWriterAlways},
		{"fs.truncate", 0, "", -1, "", literalWriterAlways},
		{"fs.truncateSync", 0, "", -1, "", literalWriterAlways},
		{"fs.createWriteStream", 0, "", -1, "", literalWriterAlways},
		{"fs.open", 0, "", 1, "", literalWriterNodeOpen},
		{"fs.openSync", 0, "", 1, "", literalWriterNodeOpen},
		{"fs.promises.writeFile", 0, "", -1, "", literalWriterAlways},
		{"fs.promises.appendFile", 0, "", -1, "", literalWriterAlways},
		{"fs.promises.copyFile", 1, "", -1, "", literalWriterAlways},
		{"fs.promises.cp", 1, "", -1, "", literalWriterFileOrDirectory},
		{"fs.promises.rename", 1, "", -1, "", literalWriterAlways},
		{"fs.promises.truncate", 0, "", -1, "", literalWriterAlways},
		{"fs.promises.open", 0, "", 1, "", literalWriterNodeOpen},
	},
	"perl": {
		{"open", 2, "", 1, "", literalWriterPerlOpen},
		{"sysopen", 1, "", 2, "", literalWriterFlags},
		{"File::Copy::copy", 1, "", -1, "", literalWriterDestinationDirectory},
		{"File::Copy::move", 1, "", -1, "", literalWriterDestinationDirectory},
		{"File::Copy::cp", 1, "", -1, "", literalWriterDestinationDirectory},
		{"File::Copy::mv", 1, "", -1, "", literalWriterDestinationDirectory},
		{"rename", 1, "", -1, "", literalWriterAlways},
		{"truncate", 0, "", -1, "", literalWriterAlways},
	},
	"ruby": {
		{"File.write", 0, "", -1, "", literalWriterAlways},
		{"IO.write", 0, "", -1, "", literalWriterAlways},
		{"File.binwrite", 0, "", -1, "", literalWriterAlways},
		{"IO.binwrite", 0, "", -1, "", literalWriterAlways},
		{"File.open", 0, "", 1, "", literalWriterMode},
		{"FileUtils.cp", 1, "", -1, "", literalWriterDestinationDirectory},
		{"FileUtils.mv", 1, "", -1, "", literalWriterDestinationDirectory},
		{"FileUtils.copy_file", 1, "", -1, "", literalWriterAlways},
		{"File.rename", 1, "", -1, "", literalWriterAlways},
		{"File.truncate", 0, "", -1, "", literalWriterAlways},
	},
}

var (
	literalCallName          = regexp.MustCompile(`\b[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::)[A-Za-z_$][A-Za-z0-9_$]*)*\s*\(`)
	literalImportAlias       = regexp.MustCompile(`\bimport\s+(os|io|shutil|pathlib|builtins|subprocess|logging)\s+as\s+([A-Za-z_]\w*)`)
	literalFromImport        = regexp.MustCompile(`\bfrom\s+(os|io|shutil|pathlib|builtins|logging)\s+import\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?`)
	literalPythonBinding     = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\b`)
	literalNodeRequire       = regexp.MustCompile(`\brequire\s*\(\s*['"](?:node:)?fs(?:/promises)?['"]\s*\)`)
	literalNodeProcess       = regexp.MustCompile(`\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)`)
	literalNodeBinding       = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(fs(?:\.promises)?(?:\.[A-Za-z_$][\w$]*)?)\b`)
	literalNodeDestructure   = regexp.MustCompile(`\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(fs(?:\.promises)?)\b`)
	literalNodeNamedImport   = regexp.MustCompile(`\bimport\s*\{([^}]+)\}\s*from\s*['"](?:node:)?fs(?:/promises)?['"]`)
	literalNodeDefaultImport = regexp.MustCompile(`\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?fs(?:/promises)?['"]`)
	literalPathMethod        = regexp.MustCompile(`^((?:\s*/\s*(?:"[^"]*"|'[^']*'))*)\s*\)?\s*\.\s*(open|write_text|write_bytes|touch)\s*\(`)
	literalReadOnlyFlag      = regexp.MustCompile(`^(?:(?:os|fs\.constants)\.)?O_RDONLY$`)
	literalPerlBareOpen      = regexp.MustCompile(`\bopen\s+(?:my\s+)?\$?\w+\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	literalPerlBareOpen2     = regexp.MustCompile(`\bopen\s+(?:my\s+)?\$?\w+\s*,\s*['"](?:>>|>|\+<)([^'"]+)['"]`)
	literalPerlCopyUse       = regexp.MustCompile(`\buse\s+File::Copy(?:\s+qw\(([^)]*)\))?`)
	literalIdentifier        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type literalShellRunnerRule struct {
	callee string
	arg    int
	flag   string
}

var literalShellRunnerRules = map[string][]literalShellRunnerRule{
	"python": {{"os.system", 0, ""}, {"subprocess.run", 0, "shell=True"}, {"subprocess.call", 0, "shell=True"}, {"subprocess.check_call", 0, "shell=True"}, {"subprocess.check_output", 0, "shell=True"}},
	"node":   {{"child_process.exec", 0, ""}, {"child_process.execSync", 0, ""}},
	"perl":   {{"system", 0, ""}},
	"awk":    {{"system", 0, ""}},
}

func literalLanguage(program string) string {
	switch {
	case program == "python" || strings.HasPrefix(program, "python3"):
		return "python"
	case program == "node":
		return "node"
	case program == "perl":
		return "perl"
	case program == "ruby":
		return "ruby"
	}
	return ""
}

func literalWriterBindings(language, code string) (string, map[string]string) {
	aliases := map[string]string{}
	switch language {
	case "python":
		for _, match := range literalImportAlias.FindAllStringSubmatch(code, -1) {
			aliases[match[2]] = match[1]
		}
		for _, match := range literalFromImport.FindAllStringSubmatch(code, -1) {
			name := match[2]
			if match[3] != "" {
				name = match[3]
			}
			aliases[name] = match[1] + "." + match[2]
		}
		for _, match := range literalPythonBinding.FindAllStringSubmatch(code, -1) {
			canonical := literalCanonicalName(match[2], aliases)
			for _, rule := range literalWriterRules[language] {
				if rule.callee == canonical {
					aliases[match[1]] = canonical
					break
				}
			}
		}
	case "node":
		code = literalNodeRequire.ReplaceAllStringFunc(code, func(call string) string {
			if strings.Contains(call, "/promises") {
				return "fs.promises"
			}
			return "fs"
		})
		code = literalNodeProcess.ReplaceAllString(code, "child_process")
		for _, match := range literalNodeBinding.FindAllStringSubmatch(code, -1) {
			aliases[match[1]] = match[2]
		}
		for _, match := range literalNodeDestructure.FindAllStringSubmatch(code, -1) {
			literalNamedBindings(aliases, match[1], match[2], false)
		}
		for _, match := range literalNodeNamedImport.FindAllStringSubmatch(code, -1) {
			module := "fs"
			if strings.Contains(match[0], "/promises") {
				module = "fs.promises"
			}
			literalNamedBindings(aliases, match[1], module, true)
		}
		for _, match := range literalNodeDefaultImport.FindAllStringSubmatch(code, -1) {
			module := "fs"
			if strings.Contains(match[0], "/promises") {
				module = "fs.promises"
			}
			aliases[match[1]] = module
		}
	case "perl":
		for _, match := range literalPerlCopyUse.FindAllStringSubmatch(code, -1) {
			names := []string{"copy", "move"}
			if match[1] != "" {
				names = strings.Fields(match[1])
			}
			for _, name := range names {
				if name == "copy" || name == "move" || name == "cp" || name == "mv" {
					aliases[name] = "File::Copy::" + name
				}
			}
		}
	}
	return code, aliases
}

func literalNamedBindings(aliases map[string]string, names, module string, esm bool) {
	for _, item := range strings.Split(names, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		separator := ":"
		if esm {
			separator = " as "
		}
		parts := strings.SplitN(item, separator, 2)
		name, local := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[0])
		if len(parts) == 2 {
			local = strings.TrimSpace(parts[1])
		}
		if name != "" && local != "" {
			aliases[local] = module + "." + name
		}
	}
}

func literalCanonicalName(name string, aliases map[string]string) string {
	first := strings.IndexAny(name, ".:")
	if first < 0 {
		if canonical, ok := aliases[name]; ok {
			return canonical
		}
		return name
	}
	if canonical, ok := aliases[name[:first]]; ok {
		return canonical + name[first:]
	}
	return name
}

func literalWriterArg(args []string, index int, keyword string) string {
	if keyword != "" {
		for _, arg := range args {
			if name, value, ok := literalKeywordArgument(arg); ok && name == keyword {
				return value
			}
		}
	}
	position := 0
	for _, arg := range args {
		if _, _, ok := literalKeywordArgument(arg); ok {
			continue
		}
		if position == index {
			return arg
		}
		position++
	}
	return ""
}

func literalKeywordArgument(arg string) (string, string, bool) {
	left, right, found := strings.Cut(arg, "=")
	name := strings.TrimSpace(left)
	if !found || name == "" || strings.HasPrefix(right, "=") {
		return "", "", false
	}
	for i, char := range name {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char == '_' ||
			i > 0 && char >= '0' && char <= '9') {
			return "", "", false
		}
	}
	return name, strings.TrimSpace(right), true
}

func literalPythonBoundPath(prefix, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if !literalIdentifier.MatchString(name) {
		return "", false
	}
	assignments := regexp.MustCompile(`\b`+regexp.QuoteMeta(name)+`\s*=`).FindAllStringIndex(prefix, -1)
	value, found := "", false
	for _, assignment := range assignments {
		if assignment[1] < len(prefix) && prefix[assignment[1]] == '=' {
			continue
		}
		start := strings.LastIndexAny(prefix[:assignment[0]], ";\n") + 1
		if strings.TrimSpace(prefix[start:assignment[0]]) != "" {
			return "", false
		}
		right := prefix[assignment[1]:]
		if end := strings.IndexAny(right, ";\n"); end >= 0 {
			right = right[:end]
		}
		literal, ok := literalExpression("python", right)
		if !ok {
			return "", false
		}
		value, found = literal, true
	}
	return value, found
}

func literalWriterEnabled(rule literalWriterRule, args []string) bool {
	if rule.kind == literalWriterAlways || rule.kind == literalWriterDestinationDirectory ||
		rule.kind == literalWriterDirectory || rule.kind == literalWriterFileOrDirectory {
		return true
	}
	modeArg := literalWriterArg(args, rule.modeArg, rule.modeKeyword)
	switch rule.kind {
	case literalWriterMode, literalWriterNodeOpen:
		if modeArg == "" {
			return false
		}
		if rule.kind == literalWriterNodeOpen {
			if flags, err := strconv.ParseUint(strings.TrimSpace(modeArg), 0, 32); err == nil {
				return flags&(1|2|64|512|1024) != 0
			}
		}
		mode, ok := literalString(modeArg)
		if !ok {
			if rule.kind == literalWriterNodeOpen && literalReadOnlyFlag.MatchString(strings.TrimSpace(modeArg)) {
				return false
			}
			return true
		}
		if rule.kind == literalWriterNodeOpen {
			return strings.ContainsAny(mode, "wax+")
		}
		return literalWriteMode(mode)
	case literalWriterPerlOpen:
		mode, ok := literalExpression("perl", modeArg)
		return !ok && modeArg != "" || ok && (mode == ">" || mode == ">>" || mode == "+<" || len(args) == 2 && (strings.HasPrefix(mode, ">") || strings.HasPrefix(mode, "+<")))
	case literalWriterFlags:
		return literalOSWriteFlags(modeArg) || modeArg != "" && modeArg != "0" && !literalReadOnlyFlag.MatchString(strings.TrimSpace(modeArg))
	}
	return false
}

func literalInterpreterWrites(language, code, cwd string) ([]string, bool) {
	if language == "" {
		return nil, false
	}
	if len(code) > maxAnalysisBytes {
		return nil, true
	}
	code, aliases := literalWriterBindings(language, code)
	var paths []string
	unknown := false
	for _, loc := range literalCallName.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		name := literalCanonicalName(strings.TrimSpace(code[loc[0]:loc[1]-1]), aliases)
		call, ok := literalBoundedCall(code, loc[1]-1)
		if !ok {
			continue
		}
		args := literalCallArgs(call)
		for _, rule := range literalWriterRules[language] {
			if name != rule.callee || !literalWriterEnabled(rule, args) {
				continue
			}
			pathArg := literalWriterArg(args, rule.pathArg, rule.pathKeyword)
			if language == "perl" && name == "open" && len(args) == 2 {
				if mode, ok := literalString(args[1]); ok && (strings.HasPrefix(mode, ">") || strings.HasPrefix(mode, "+<")) {
					pathArg = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(mode, ">"), ">"), "+<")
					paths = append(paths, pathArg)
				} else {
					unknown = true
				}
				continue
			}
			path, knownPath := literalExpression(language, pathArg)
			if !knownPath && language == "python" {
				path, knownPath = literalPythonBoundPath(code[:loc[0]], pathArg)
			}
			if knownPath {
				if rule.kind != literalWriterDirectory {
					paths = append(paths, path)
				}
				if rule.kind == literalWriterDestinationDirectory {
					if info, err := os.Stat(OperandPath(path, cwd)); err == nil && info.IsDir() {
						if source, ok := literalExpression(language, literalWriterArg(args, 0, "src")); ok {
							paths = append(paths, filepath.Join(path, filepath.Base(source)))
						} else {
							unknown = true
						}
					} else if err != nil && !os.IsNotExist(err) {
						unknown = true
					}
				}
				if rule.kind == literalWriterDirectory || rule.kind == literalWriterFileOrDirectory {
					for _, name := range AuthorizedKeysFiles {
						paths = append(paths, filepath.Join(path, name))
					}
				}
			} else if pathArg != "" {
				if name == "shutil.copyfileobj" && strings.HasPrefix(strings.TrimSpace(pathArg), "open(") {
					continue
				}
				unknown = true
			}
		}
		for _, rule := range literalShellRunnerRules[language] {
			if name != rule.callee {
				continue
			}
			if rule.flag != "" {
				found := false
				for _, arg := range args[1:] {
					if strings.ReplaceAll(arg, " ", "") == rule.flag {
						found = true
					}
				}
				if !found {
					continue
				}
			}
			if rule.arg >= len(args) {
				continue
			}
			script, ok := literalString(args[rule.arg])
			if !ok {
				unknown = true
				continue
			}
			writes, parsed, dynamic := ShellWriteOperands(script, ".", "")
			paths = append(paths, writes...)
			unknown = unknown || !parsed || dynamic
			for _, operand := range ShellExtraWriteOperands(script, ".", "") {
				paths = append(paths, operand.Path)
			}
		}
		if language == "python" && name == "pathlib.Path" {
			start := loc[1] - 1 + len(call)
			if start >= len(code) {
				continue
			}
			method := literalPathMethod.FindStringSubmatchIndex(code[start:])
			if method == nil {
				continue
			}
			methodName := code[start+method[4] : start+method[5]]
			methodCall, ok := literalBoundedCall(code, start+method[1]-1)
			if !ok {
				continue
			}
			for _, rule := range literalWriterRules[language] {
				if rule.callee != "pathlib.Path."+methodName || !literalWriterEnabled(rule, literalCallArgs(methodCall)) {
					continue
				}
				if len(args) == 0 {
					continue
				}
				pathExpression := "Path(" + args[0] + ")" + code[start+method[2]:start+method[3]]
				if path, ok := literalExpression(language, pathExpression); ok {
					paths = append(paths, path)
				} else {
					unknown = true
				}
			}
		}
	}
	if language == "perl" {
		for _, pattern := range []*regexp.Regexp{literalPerlBareOpen, literalPerlBareOpen2} {
			for _, match := range pattern.FindAllStringSubmatchIndex(code, -1) {
				if literalCodePosition(code, match[0]) {
					paths = append(paths, code[match[2]:match[3]])
				}
			}
		}
	}
	return paths, unknown
}
