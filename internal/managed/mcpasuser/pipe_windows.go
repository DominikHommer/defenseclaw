// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package mcpasuser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// maxConcurrentSessions bounds the servers started at once.
const maxConcurrentSessions = 4

const pipeBufferBytes = 64 << 10

var (
	modAdvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modAdvapi32.NewProc("ImpersonateNamedPipeClient")
)

// Serve accepts relay connections on the as-user pipe of gatewayService
// until ctx ends. Only a process whose token carries the gateway's service
// SID may connect: the pipe access list says so, and each client's token is
// checked again before its request is read.
func Serve(ctx context.Context, gatewayService string, start Starter, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	name, err := PipeName(gatewayService)
	if err != nil {
		return err
	}
	gatewaySID, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + gatewayService)
	if err != nil || gatewaySID == nil {
		return errors.New("resolve the gateway service SID for the MCP as-user pipe")
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:SYD:P(A;;GA;;;SY)(A;;GRGW;;;" + gatewaySID.String() + ")")
	if err != nil {
		return errors.New("build the MCP as-user pipe security descriptor")
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	slots := make(chan struct{}, maxConcurrentSessions)
	var active sync.WaitGroup
	defer active.Wait()
	first := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case slots <- struct{}{}:
		}
		pipe, err := createPipe(name, &attributes, first)
		runtime.KeepAlive(descriptor)
		if err != nil {
			<-slots
			// FILE_FLAG_FIRST_PIPE_INSTANCE fails when another process
			// created the name first: never serve beside it.
			return fmt.Errorf("create the MCP as-user pipe %s: %w", name, err)
		}
		first = false
		if err := connectPipe(ctx, pipe); err != nil {
			_ = windows.CloseHandle(pipe)
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		var clientPID uint32
		_ = windows.GetNamedPipeClientProcessId(pipe, &clientPID)
		if err := verifyPipeClient(pipe, gatewaySID); err != nil {
			logf("[mcp-as-user] refused pipe client pid %d: %v", clientPID, err)
			_ = windows.DisconnectNamedPipe(pipe)
			_ = windows.CloseHandle(pipe)
			<-slots
			continue
		}
		active.Add(1)
		go func(pipe windows.Handle, pid uint32) {
			defer active.Done()
			defer func() { <-slots }()
			conn := os.NewFile(uintptr(pipe), name)
			defer conn.Close()
			request, err := ServeConn(ctx, conn, start, SessionLimit)
			if err != nil {
				logf("[mcp-as-user] server %q of %s (%s) for pid %d: %v", request.Name, request.SID, request.Connector, pid, err)
			}
		}(pipe, clientPID)
	}
}

func createPipe(name string, attributes *windows.SecurityAttributes, first bool) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(pointer, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, pipeBufferBytes, pipeBufferBytes, 0, attributes)
}

// connectPipe waits for a client on pipe until ctx ends.
func connectPipe(ctx context.Context, pipe windows.Handle) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(pipe, overlapped)
	if err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return err
	}
	for {
		wait, waitErr := windows.WaitForSingleObject(event, 100)
		if waitErr != nil {
			_ = windows.CancelIoEx(pipe, overlapped)
			return waitErr
		}
		if wait == windows.WAIT_OBJECT_0 {
			var count uint32
			return windows.GetOverlappedResult(pipe, overlapped, &count, false)
		}
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(pipe, overlapped)
			_, _ = windows.WaitForSingleObject(event, windows.INFINITE)
			return ctx.Err()
		}
		runtime.KeepAlive(overlapped)
	}
}

// verifyPipeClient impersonates the connected client and checks that its
// token carries the gateway's service SID: the gateway and the scanner
// runtime and relay it starts have it, no user process does.
func verifyPipeClient(pipe windows.Handle, gatewaySID *windows.SID) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if ret, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe)); ret == 0 {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("impersonate the pipe client: %v", callErr)
			return
		}
		var token windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		var gateway bool
		if err == nil {
			gateway, err = managed.WindowsTokenRunsAsService(token, gatewaySID)
			token.Close()
		}
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Never return an impersonating thread to the pool; the runtime
			// ends this locked thread when the goroutine exits.
			result <- fmt.Errorf("revert the pipe client impersonation: %w", revertErr)
			return
		}
		runtime.UnlockOSThread()
		switch {
		case err != nil:
			result <- err
		case !gateway:
			result <- errors.New("the client is not the DefenseClaw gateway service")
		default:
			result <- nil
		}
	}()
	return <-result
}

// Dial connects to the enumerator's as-user pipe of gatewayService and
// checks that the process serving it runs as LocalSystem, so a pipe a user
// created under that name is never used.
func Dial(ctx context.Context, gatewayService string) (io.ReadWriteCloser, error) {
	name, err := PipeName(gatewayService)
	if err != nil {
		return nil, err
	}
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for {
		handle, openErr := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if openErr == nil {
			if err := verifyPipeServer(handle); err != nil {
				_ = windows.CloseHandle(handle)
				return nil, err
			}
			return os.NewFile(uintptr(handle), name), nil
		}
		if !errors.Is(openErr, windows.ERROR_PIPE_BUSY) && !errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
			return nil, fmt.Errorf("open %s: %w", name, openErr)
		}
		select {
		case <-ctx.Done():
			if errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
				return nil, errors.New("the DefenseClaw hook enumerator service is not serving MCP as-user scans; " +
					"it starts them once it runs (Setup /repair restarts it)")
			}
			return nil, fmt.Errorf("open %s: %w", name, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func verifyPipeServer(pipe windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil || pid == 0 {
		return errors.New("the MCP as-user pipe server is unknown")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open the MCP as-user pipe server: %w", err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("read the MCP as-user pipe server token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("the MCP as-user pipe is not served by a LocalSystem service")
	}
	return nil
}
