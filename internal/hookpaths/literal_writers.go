// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
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
		{"open", 0, "file", 1, "mode", literalWriterMode},
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
	},
}

var (
	literalCallName          = regexp.MustCompile(`\b[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::)[A-Za-z_$][A-Za-z0-9_$]*)*\s*\(`)
	literalImportAlias       = regexp.MustCompile(`\bimport\s+(os|io|shutil|pathlib)\s+as\s+([A-Za-z_]\w*)`)
	literalFromImport        = regexp.MustCompile(`\bfrom\s+(os|io|shutil|pathlib)\s+import\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?`)
	literalNodeRequire       = regexp.MustCompile(`\brequire\s*\(\s*['"](?:node:)?fs(?:/promises)?['"]\s*\)`)
	literalNodeBinding       = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(fs(?:\.promises)?)\b`)
	literalNodeDestructure   = regexp.MustCompile(`\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(fs(?:\.promises)?)\b`)
	literalNodeNamedImport   = regexp.MustCompile(`\bimport\s*\{([^}]+)\}\s*from\s*['"](?:node:)?fs(?:/promises)?['"]`)
	literalNodeDefaultImport = regexp.MustCompile(`\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?fs(?:/promises)?['"]`)
	literalPathMethod        = regexp.MustCompile(`^\s*\.\s*(open|write_text|write_bytes)\s*\(`)
	literalReadOnlyFlag      = regexp.MustCompile(`^(?:(?:os|fs\.constants)\.)?O_RDONLY$`)
	literalPerlOpen          = regexp.MustCompile(`\bopen\s*(?:\(\s*)?(?:my\s+)?\$?\w+\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	literalPerlOpen2         = regexp.MustCompile(`\bopen\s*(?:\(\s*)?(?:my\s+)?\$?\w+\s*,\s*['"](?:>>|>)([^'"]+)['"]`)
)

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
	case "node":
		code = literalNodeRequire.ReplaceAllStringFunc(code, func(call string) string {
			if strings.Contains(call, "/promises") {
				return "fs.promises"
			}
			return "fs"
		})
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
		if strings.Contains(code, "use File::Copy") {
			for _, name := range []string{"copy", "move", "cp", "mv"} {
				aliases[name] = "File::Copy::" + name
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
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == keyword {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	if index >= 0 && index < len(args) {
		return args[index]
	}
	return ""
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
		mode, ok := literalString(modeArg)
		if !ok {
			return true
		}
		if rule.kind == literalWriterNodeOpen {
			return strings.ContainsAny(mode, "wx+")
		}
		return literalWriteMode(mode)
	case literalWriterPerlOpen:
		mode, ok := literalString(modeArg)
		return !ok && modeArg != "" || ok && (mode == ">" || mode == ">>" || mode == "+<" || len(args) == 2 && (strings.HasPrefix(mode, ">") || strings.HasPrefix(mode, "+<")))
	case literalWriterFlags:
		return literalOSWriteFlags(modeArg) || modeArg != "" && modeArg != "0" && !literalReadOnlyFlag.MatchString(strings.TrimSpace(modeArg))
	}
	return false
}

func literalInterpreterWrites(language, code string) ([]string, bool) {
	if language == "" {
		return nil, false
	}
	if len(code) > 16<<10 {
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
				}
				continue
			}
			if path, ok := literalString(pathArg); ok {
				if rule.kind != literalWriterDirectory {
					paths = append(paths, path)
				}
				if rule.kind == literalWriterDestinationDirectory {
					if len(args) > 0 {
						if source, ok := literalString(args[0]); ok {
							paths = append(paths, filepath.Join(path, filepath.Base(source)))
						}
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
		if language == "python" && name == "pathlib.Path" {
			start := loc[1] - 1 + len(call)
			if start >= len(code) {
				continue
			}
			method := literalPathMethod.FindStringSubmatchIndex(code[start:])
			if method == nil {
				continue
			}
			methodName := code[start+method[2] : start+method[3]]
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
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				} else {
					unknown = true
				}
			}
		}
	}
	if language == "perl" {
		for _, match := range literalPerlOpen.FindAllStringSubmatchIndex(code, -1) {
			if literalCodePosition(code, match[0]) {
				paths = append(paths, code[match[2]:match[3]])
			}
		}
		for _, match := range literalPerlOpen2.FindAllStringSubmatchIndex(code, -1) {
			if literalCodePosition(code, match[0]) {
				paths = append(paths, code[match[2]:match[3]])
			}
		}
	}
	return paths, unknown
}
