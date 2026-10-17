// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
	"golang.org/x/sys/windows"
)

// mcpAsUserActiveProcessLimit bounds the processes one server may run
// (npx starts node, uvx a Python).
const mcpAsUserActiveProcessLimit = 64

// WindowsMCPAsUserStarter starts, as the enrolled user, a local MCP server
// that the hook enumerator published for that user, for the gateway's
// admission scan (#1164). It runs in the enumerator service (LocalSystem).
//
// It starts only the definition in its own published record (the request
// names it, its digest pins it), only an npx or uvx launcher with a package
// argument, only with the user's own signed-in session token, and only in a
// folder it checked while impersonating the user: inside the project or the
// user's profile, in no other profile, with no link or reparse point on the
// way. The server and everything it starts run in a job that ends with the
// scan. Any failure refuses the start, and the gateway blocks the server.
type WindowsMCPAsUserStarter struct {
	// Manifest returns the enrolled targets.
	Manifest func() (Manifest, error)
	// AuthorizationDir returns the hook guardian authorization folder that
	// holds the published records.
	AuthorizationDir func() (string, error)
}

// Seams for tests.
var (
	windowsMCPAsUserReadSpool = func(dir, sid, connector string) ([]config.MCPServerEntry, *ClaudeStateUnreadable, error) {
		return readMCPSpool(dir, sid, connector, managed.ValidateTrustedFilePath)
	}
	windowsMCPAsUserSessionToken = windowsEnterpriseSignedInTargetTokenResolver
	windowsMCPAsUserStartProcess = startWindowsMCPAsUserProcess
)

// Start implements mcpasuser.Starter.
func (s WindowsMCPAsUserStarter) Start(_ context.Context, request mcpasuser.Request) (mcpasuser.Session, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if s.Manifest == nil || s.AuthorizationDir == nil {
		return nil, errors.New("the hook enumerator has no enrollment to check the request against")
	}
	manifest, err := s.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read the enrollment manifest: %w", err)
	}
	target, homes, ok := mcpAsUserTarget(manifest, request)
	if !ok {
		return nil, fmt.Errorf("account %s is not enrolled for %s", request.SID, request.Connector)
	}
	home := filepath.Clean(strings.TrimSpace(target.UserHome))
	account := strings.TrimSpace(target.User)
	if account == "" {
		account = request.SID
	}
	authorizationDir, err := s.AuthorizationDir()
	if err != nil {
		return nil, err
	}
	dir := ClaudeMCPSpoolDir(authorizationDir)
	if request.Connector == "kiro" {
		dir = KiroMCPSpoolDir(authorizationDir)
	}
	servers, unreadable, err := windowsMCPAsUserReadSpool(dir, request.SID, request.Connector)
	if err != nil {
		return nil, fmt.Errorf("read the MCP servers published for %s: %w", account, err)
	}
	if unreadable != nil {
		return nil, fmt.Errorf("the MCP servers of %s are unknown: %s (%s)", account, unreadable.Path, unreadable.Reason)
	}
	entry, err := findMCPAsUserServer(servers, request)
	if err != nil {
		return nil, err
	}
	entry.Home = home
	launcher, err := checkMCPAsUserDefinition(entry)
	if err != nil {
		return nil, fmt.Errorf("MCP server %q is not started: %w", entry.Name, err)
	}

	sid, err := validateWindowsEnterpriseTargetSID(request.SID)
	if err != nil {
		return nil, err
	}
	impersonation, err := windowsMCPAsUserSessionToken(sid)
	if err != nil {
		var signedOut *WindowsTargetSessionUnavailableError
		if errors.As(err, &signedOut) {
			return nil, fmt.Errorf("%s is not signed in, so their MCP server %q cannot be started as them; "+
				"it is scanned again once they sign in", account, entry.Name)
		}
		return nil, fmt.Errorf("get the session token of %s: %w", account, err)
	}
	defer impersonation.Close()
	if err := validateWindowsEnterpriseTargetToken(impersonation, sid); err != nil {
		return nil, err
	}
	if err := validateWindowsEnterpriseTokenProfile(impersonation, home); err != nil {
		return nil, err
	}
	var primary windows.Token
	if err := windows.DuplicateTokenEx(impersonation,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return nil, fmt.Errorf("make a process token for %s: %w", account, err)
	}
	defer primary.Close()
	userEnv, err := primary.Environ(false)
	if err != nil {
		return nil, fmt.Errorf("read the environment of %s: %w", account, err)
	}
	env := mergeMCPAsUserEnv(userEnv, entry.Env)

	// The folder and the launcher are resolved as the user: the user's
	// access decides, so a junction into another profile fails.
	var workDir, launcherPath string
	if err := runWindowsEnterpriseImpersonatedCallback(impersonation, sid, func() error {
		dir, refused := vetClaudeMCPWorkDir(entry, home, otherWindowsHomes(homes, home), windowsClaudeMCPWorkDirChecks)
		if dir == "" && refused != "" {
			return fmt.Errorf("MCP server %q is not started in %s", entry.Name, refused)
		}
		if dir == "" {
			// A user-scope server names no folder: it starts in the profile.
			vetted, err := vetClaudeMCPWorkDirCandidate(home, home, []string{home}, otherWindowsHomes(homes, home), windowsClaudeMCPWorkDirChecks)
			if err != nil {
				return fmt.Errorf("MCP server %q is not started in %s: %v", entry.Name, home, err)
			}
			dir = vetted
		}
		workDir = dir
		found, err := findMCPLauncherOnPath(launcher.file, mcpAsUserEnvValue(env, "PATH"), func(path string) bool {
			info, err := os.Stat(path)
			return err == nil && info.Mode().IsRegular()
		})
		if err != nil {
			return fmt.Errorf("MCP server %q is not started: %w", entry.Name, err)
		}
		launcherPath = found
		return nil
	}); err != nil {
		return nil, err
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	argv, err := mcpAsUserArgv(launcher, launcherPath, filepath.Join(systemDir, "cmd.exe"), entry.Args)
	if err != nil {
		return nil, fmt.Errorf("MCP server %q is not started: %w", entry.Name, err)
	}
	return windowsMCPAsUserStartProcess(primary, argv, env, workDir)
}

// mcpAsUserTarget is the enabled manifest row of the request's account and
// connector, and every enrolled profile.
func mcpAsUserTarget(manifest Manifest, request mcpasuser.Request) (ManifestTarget, []string, bool) {
	var homes []string
	var found ManifestTarget
	ok := false
	for _, target := range manifest.Targets {
		home := strings.TrimSpace(target.UserHome)
		if filepath.IsAbs(home) {
			homes = append(homes, filepath.Clean(home))
		}
		if ok || !strings.EqualFold(strings.TrimSpace(target.SID), request.SID) ||
			!strings.EqualFold(strings.TrimSpace(target.Connector), request.Connector) ||
			(target.Enabled != nil && !*target.Enabled) || !filepath.IsAbs(home) {
			continue
		}
		found, ok = target, true
	}
	return found, homes, ok
}

// windowsMCPAsUserSession is a server started by startWindowsMCPAsUserProcess.
type windowsMCPAsUserSession struct {
	process, job          windows.Handle
	stdin, stdout, stderr *os.File
	killOnce, releaseOnce sync.Once
}

func (s *windowsMCPAsUserSession) Stdin() io.WriteCloser { return s.stdin }
func (s *windowsMCPAsUserSession) Stdout() io.Reader     { return s.stdout }
func (s *windowsMCPAsUserSession) Stderr() io.Reader     { return s.stderr }

func (s *windowsMCPAsUserSession) Wait() (int, error) {
	if _, err := windows.WaitForSingleObject(s.process, windows.INFINITE); err != nil {
		return 1, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(s.process, &code); err != nil {
		return 1, err
	}
	return int(int32(code)), nil
}

func (s *windowsMCPAsUserSession) Kill() {
	s.killOnce.Do(func() { _ = windows.TerminateJobObject(s.job, 1) })
}

func (s *windowsMCPAsUserSession) Close() {
	s.Kill()
	s.releaseOnce.Do(func() {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		_ = s.stderr.Close()
		_ = windows.CloseHandle(s.process)
		_ = windows.CloseHandle(s.job)
	})
}

// startWindowsMCPAsUserProcess starts argv with the user's primary token in
// workDir, hidden on the user's session desktop, in a job that kills every
// process of the server when the job handle closes. The child gets only its
// three stdio pipe ends.
func startWindowsMCPAsUserProcess(token windows.Token, argv, env []string, workDir string) (_ mcpasuser.Session, err error) {
	if len(argv) == 0 {
		return nil, errors.New("no command to start")
	}
	commandLine := make([]string, len(argv))
	for i, arg := range argv {
		commandLine[i] = windows.EscapeArg(arg)
	}
	appName, err := windows.UTF16PtrFromString(argv[0])
	if err != nil {
		return nil, err
	}
	cmdLine, err := windows.UTF16PtrFromString(strings.Join(commandLine, " "))
	if err != nil {
		return nil, err
	}
	dirPtr, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return nil, err
	}
	block, err := windowsEnvironmentBlock(env)
	if err != nil {
		return nil, err
	}
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return nil, err
	}

	var closers []windows.Handle
	closeAll := func() {
		for _, handle := range closers {
			_ = windows.CloseHandle(handle)
		}
	}
	inherit := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	pipe := func(childReads bool) (parent, child windows.Handle, err error) {
		var readEnd, writeEnd windows.Handle
		if err := windows.CreatePipe(&readEnd, &writeEnd, &inherit, 0); err != nil {
			return 0, 0, err
		}
		closers = append(closers, readEnd, writeEnd)
		parent, child = writeEnd, readEnd
		if !childReads {
			parent, child = readEnd, writeEnd
		}
		if err := windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			return 0, 0, err
		}
		return parent, child, nil
	}
	stdinParent, stdinChild, err := pipe(true)
	if err == nil {
		var stdoutParent, stdoutChild, stderrParent, stderrChild windows.Handle
		if stdoutParent, stdoutChild, err = pipe(false); err == nil {
			if stderrParent, stderrChild, err = pipe(false); err == nil {
				return startWindowsMCPAsUserChild(token, appName, cmdLine, block, dirPtr, desktop,
					[3]windows.Handle{stdinChild, stdoutChild, stderrChild},
					[3]windows.Handle{stdinParent, stdoutParent, stderrParent}, &closers, closeAll)
			}
		}
	}
	closeAll()
	return nil, fmt.Errorf("create the server stdio pipes: %w", err)
}

func startWindowsMCPAsUserChild(
	token windows.Token,
	appName, cmdLine, block, dirPtr, desktop *uint16,
	child, parent [3]windows.Handle,
	closers *[]windows.Handle,
	closeAll func(),
) (mcpasuser.Session, error) {
	startup := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
		StdInput:   child[0],
		StdOutput:  child[1],
		StdErr:     child[2],
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("create the server job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
				windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
			ActiveProcessLimit: mcpAsUserActiveProcessLimit,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		closeAll()
		return nil, fmt.Errorf("limit the server job: %w", err)
	}
	var info windows.ProcessInformation
	err = withWindowsImpersonatePrivilege(func() error {
		return createWindowsProcessWithToken(token, windowsLogonWithProfile, appName, cmdLine,
			windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NEW_CONSOLE,
			block, dirPtr, &startup, &info)
	})
	if err != nil {
		_ = windows.CloseHandle(job)
		closeAll()
		if errors.Is(err, windows.ERROR_SERVICE_DISABLED) {
			return nil, errors.New("start the server as the user: the Secondary Logon (seclogon) service is disabled; " +
				"DefenseClaw needs it to start an MCP server in a user profile as that user for its scan")
		}
		return nil, fmt.Errorf("start the server as the user: %w", err)
	}
	defer windows.CloseHandle(info.Thread)
	if err := windows.AssignProcessToJobObject(job, info.Process); err != nil {
		_ = windows.TerminateProcess(info.Process, 1)
		_ = windows.CloseHandle(info.Process)
		_ = windows.CloseHandle(job)
		closeAll()
		return nil, fmt.Errorf("put the server in its job: %w", err)
	}
	if _, err := windows.ResumeThread(info.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(info.Process)
		_ = windows.CloseHandle(job)
		closeAll()
		return nil, fmt.Errorf("resume the server: %w", err)
	}
	// The child holds its ends now; the parent keeps only its own.
	for _, handle := range child {
		_ = windows.CloseHandle(handle)
	}
	*closers = nil
	return &windowsMCPAsUserSession{
		process: info.Process, job: job,
		stdin:  os.NewFile(uintptr(parent[0]), "mcp-server-stdin"),
		stdout: os.NewFile(uintptr(parent[1]), "mcp-server-stdout"),
		stderr: os.NewFile(uintptr(parent[2]), "mcp-server-stderr"),
	}, nil
}

// CreateProcessWithTokenW starts a process with another user's token
// through the Secondary Logon service. It needs only SeImpersonatePrivilege,
// which the enumerator service already holds, so no service privilege
// changes and an upgrade or a rollback keeps the service configuration.
var (
	modWindowsMCPAsUserAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	procCreateProcessWithTokenW = modWindowsMCPAsUserAdvapi32.NewProc("CreateProcessWithTokenW")
)

// windowsLogonWithProfile is LOGON_WITH_PROFILE: the user's registry hive is
// loaded for the process, as it is for the user's own programs.
const windowsLogonWithProfile = 0x00000001

func createWindowsProcessWithToken(
	token windows.Token, logonFlags uint32, appName, cmdLine *uint16, creationFlags uint32,
	env, currentDir *uint16, startup *windows.StartupInfo, info *windows.ProcessInformation,
) error {
	if err := procCreateProcessWithTokenW.Find(); err != nil {
		return err
	}
	ret, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(token), uintptr(logonFlags), uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(cmdLine)),
		uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)),
		uintptr(unsafe.Pointer(startup)), uintptr(unsafe.Pointer(info)))
	runtime.KeepAlive(startup)
	if ret == 0 {
		if callErr == nil || callErr == windows.ERROR_SUCCESS {
			return errors.New("CreateProcessWithTokenW failed")
		}
		return callErr
	}
	return nil
}

// withWindowsImpersonatePrivilege runs fn on a locked thread with
// SeImpersonatePrivilege enabled, which CreateProcessWithTokenW requires.
func withWindowsImpersonatePrivilege(fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: create a process creation token: %w", err)
			return
		}
		var token windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token)
		if err == nil {
			err = enableWindowsThreadPrivilege(token, "SeImpersonatePrivilege")
			token.Close()
		}
		if err == nil {
			err = fn()
		}
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Never return a still-impersonating thread to the pool.
			result <- errors.Join(err, fmt.Errorf("revert the process creation token: %w", revertErr))
			return
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	return <-result
}

// windowsEnvironmentBlock is env as a CreateProcess environment block.
func windowsEnvironmentBlock(env []string) (*uint16, error) {
	var block []uint16
	for _, kv := range env {
		if strings.ContainsRune(kv, 0) {
			return nil, errors.New("an environment entry contains NUL")
		}
		block = append(block, utf16.Encode([]rune(kv))...)
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	block = append(block, 0)
	return &block[0], nil
}
