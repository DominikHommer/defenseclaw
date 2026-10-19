// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && axis_private_root_probe

package namespaceinit

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const privateRootOutputLimit = 16 << 10

type privateRootCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (c *privateRootCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) > privateRootOutputLimit-len(c.data) {
		c.overflow = true
		return 0, errors.New("fixed private-root probe output bound exceeded")
	}
	c.data = append(c.data, p...)
	return len(p), nil
}

func (c *privateRootCapture) snapshot() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.data), c.overflow
}

func closePrivateRootFile(file **os.File) error {
	if *file == nil {
		return nil
	}
	err := (*file).Close()
	*file = nil
	return err
}

func privateRootPipe(file *os.File, wanted int) error {
	if file == nil {
		return errors.New("fixed private-root pipe absent")
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != wanted {
		return errors.New("fixed private-root pipe identity refused")
	}
	return nil
}

func privateRootChild() (resultErr error) {
	if runtime.GOARCH != "amd64" || os.Getpid() != 1 || os.Getppid() != 0 || os.Getuid() <= 0 {
		return errors.New("fixed private-root child identity refused")
	}
	self, driver := os.NewFile(6, "fixed-static-self"), os.NewFile(7, "fixed-static-exec")
	defer func() { resultErr = errors.Join(resultErr, closePrivateRootFile(&self), closePrivateRootFile(&driver)) }()
	info, err := self.Stat()
	selfSeals, sealErr := unix.FcntlInt(self.Fd(), unix.F_GET_SEALS, 0)
	driverSeals, driverSealErr := unix.FcntlInt(driver.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || sealErr != nil || driverSealErr != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > privateRootImageBudget/3 || selfSeals != seals || driverSeals != seals {
		return errors.New("fixed static self image refused")
	}
	running, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	var runningSt, heldSt, driverSt unix.Stat_t
	identityErr := errors.Join(unix.Fstat(int(running.Fd()), &runningSt), unix.Fstat(int(self.Fd()), &heldSt),
		unix.Fstat(int(driver.Fd()), &driverSt), running.Close())
	// The currently executing path is the original test binary, whereas self
	// is a sealed copy, so equality is the parent-supplied self/driver pair.
	if identityErr != nil || heldSt.Dev != driverSt.Dev || heldSt.Ino != driverSt.Ino || runningSt.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("fixed sealed static child pair differs")
	}
	hasher := sha256.New()
	var buf [64 << 10]byte
	for offset := int64(0); offset < info.Size(); {
		size := len(buf)
		if int64(size) > info.Size()-offset {
			size = int(info.Size() - offset)
		}
		n, err := self.ReadAt(buf[:size], offset)
		if n != size || err != nil {
			return errors.New("fixed static self read refused")
		}
		if _, err := hasher.Write(buf[:n]); err != nil {
			return err
		}
		offset += int64(n)
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	pinned := func(fd uintptr) PinnedSealedFile {
		return PinnedSealedFile{File: os.NewFile(fd, "fixed-sealed-role"), Size: info.Size(), SHA256: digest}
	}
	plan := PrivateRootPlan{
		Grant: os.NewFile(4, "fixed-grant"), Ready: os.NewFile(5, "fixed-ready"),
		Images: PrivateRootImages{Peer: pinned(8), Bubblewrap: pinned(9), Payload: pinned(10)},
		Devices: PrivateRootDevices{
			Null: os.NewFile(11, "fixed-null"), Zero: os.NewFile(12, "fixed-zero"), Full: os.NewFile(13, "fixed-full"),
			Random: os.NewFile(14, "fixed-random"), URandom: os.NewFile(15, "fixed-urandom"), TTY: os.NewFile(16, "fixed-tty"),
		},
	}
	if err := SetupPrivateRoot(&plan); err != nil {
		return err
	}
	if err := closePrivateRootFile(&self); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(driver.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return err
	}
	return syscall.Exec("/proc/self/fd/7", []string{"fixed-private-root-static.test", "-test.v=true", "-test.run=^TestPrivateRootStaticExecChild$"}, []string{})
}

func privateRootSealedStaticSelf() (_ *os.File, resultErr error) {
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	data, err := io.ReadAll(io.LimitReader(source, privateRootImageBudget/3+1))
	if err != nil || len(data) < 64 || int64(len(data)) > privateRootImageBudget/3 {
		return nil, errors.New("fixed self image size refused")
	}
	parsed, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("fixed self ELF refused")
	}
	defer parsed.Close()
	if parsed.Class != elf.ELFCLASS64 || parsed.Machine != elf.EM_X86_64 || parsed.Type != elf.ET_EXEC {
		return nil, errors.New("fixed static self shape refused")
	}
	executable := false
	for _, segment := range parsed.Progs {
		if segment.Type == elf.PT_INTERP || segment.Type == elf.PT_DYNAMIC {
			return nil, errors.New("fixed self external runtime refused")
		}
		if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X != 0 && parsed.Entry >= segment.Vaddr && parsed.Entry-segment.Vaddr < segment.Filesz {
			executable = true
		}
	}
	if !executable {
		return nil, errors.New("fixed static self entry refused")
	}
	fd, err := unix.MemfdCreate("fixed-private-root-static-self", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-static-self")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if n, err := file.Write(data); err != nil || n != len(data) {
		return nil, errors.New("fixed self memfd write refused")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	accepted = true
	return file, nil
}

func privateRootHeldDevices() (_ [6]*os.File, resultErr error) {
	names := [6]string{"null", "zero", "full", "random", "urandom", "tty"}
	major := [6]uint32{1, 1, 1, 1, 1, 5}
	minor := [6]uint32{3, 5, 7, 8, 9, 0}
	var files [6]*os.File
	accepted := false
	defer func() {
		if !accepted {
			for i := range files {
				resultErr = errors.Join(resultErr, closePrivateRootFile(&files[i]))
			}
		}
	}()
	for i, name := range names {
		fd, err := unix.Open("/dev/"+name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return files, err
		}
		files[i] = os.NewFile(uintptr(fd), "fixed-held-char")
		var st unix.Stat_t
		var fs unix.Statfs_t
		if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR ||
			unix.Major(st.Rdev) != major[i] || unix.Minor(st.Rdev) != minor[i] || uint64(fs.Flags)&uint64(unix.ST_NODEV) != 0 {
			return files, errors.New("fixed held host character device refused")
		}
	}
	accepted = true
	return files, nil
}

func privateRootParent() (resultErr error) {
	if runtime.GOARCH != "amd64" || os.Getpid() == 1 || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("nonroot fixed probe parent required")
	}
	proofFile, err := Capture()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closePrivateRootFile(&proofFile)) }()
	sealedSelf, err := privateRootSealedStaticSelf()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closePrivateRootFile(&sealedSelf)) }()
	heldDevices, err := privateRootHeldDevices()
	if err != nil {
		return err
	}
	defer func() {
		for i := range heldDevices {
			resultErr = errors.Join(resultErr, closePrivateRootFile(&heldDevices[i]))
		}
	}()
	var grantRead, grantWrite, readyRead, readyWrite *os.File
	defer func() {
		resultErr = errors.Join(resultErr, closePrivateRootFile(&grantRead), closePrivateRootFile(&grantWrite), closePrivateRootFile(&readyRead), closePrivateRootFile(&readyWrite))
	}()
	grantRead, grantWrite, err = os.Pipe()
	if err != nil {
		return err
	}
	readyRead, readyWrite, err = os.Pipe()
	if err != nil {
		return err
	}
	stdout, stderr := &privateRootCapture{}, &privateRootCapture{}
	pidfd := -1
	command := &exec.Cmd{
		Path: "/proc/self/exe",
		Args: []string{"fixed-private-root-probe.test", "-test.v=true", "-test.run=^TestPrivateTmpfsRootProbe$"},
		Env:  []string{}, Dir: "/", ExtraFiles: []*os.File{proofFile, grantRead, readyWrite, sealedSelf, sealedSelf, sealedSelf, sealedSelf, sealedSelf, heldDevices[0], heldDevices[1], heldDevices[2], heldDevices[3], heldDevices[4], heldDevices[5]},
		Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps:                []uintptr{unix.CAP_SYS_ADMIN},
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
			GidMappingsEnableSetgroups: false, PidFD: &pidfd,
		},
	}
	// The child death signal attaches to the thread which calls Start. Keep
	// that exact thread alive until the namespace init has been reaped.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	started, waited := false, false
	var waitDone chan error
	defer func() {
		if started && !waited {
			if pidfd >= 0 {
				signalErr := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
				if signalErr != nil && !errors.Is(signalErr, unix.ESRCH) {
					resultErr = errors.Join(resultErr, signalErr)
				}
			} else if command.Process != nil {
				resultErr = errors.Join(resultErr, command.Process.Kill())
			}
			select {
			case waitErr := <-waitDone:
				var exitErr *exec.ExitError
				if waitErr != nil && !errors.As(waitErr, &exitErr) {
					resultErr = errors.Join(resultErr, waitErr)
				}
			case <-time.After(5 * time.Second):
				resultErr = errors.Join(resultErr, errors.New("private PID namespace init was not reaped"))
			}
		}
		if pidfd >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(pidfd))
		}
		out, outOverflow := stdout.snapshot()
		diagnostics, errOverflow := stderr.snapshot()
		if outOverflow || errOverflow {
			resultErr = errors.Join(resultErr, errors.New("fixed private-root output overflow"))
		}
		if resultErr != nil {
			resultErr = fmt.Errorf("%w; bounded child stdout=%q stderr=%q", resultErr, out, diagnostics)
		}
	}()
	if err := command.Start(); err != nil {
		return fmt.Errorf("private PID namespace start: %w", err)
	}
	started = true
	waitDone = make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	if pidfd < 0 {
		return errors.New("atomic pidfd custody unavailable")
	}
	if err := errors.Join(closePrivateRootFile(&proofFile), closePrivateRootFile(&grantRead), closePrivateRootFile(&readyWrite), closePrivateRootFile(&sealedSelf)); err != nil {
		return err
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	readyMessage, err := io.ReadAll(io.LimitReader(readyRead, int64(len(PrivateRootReady)+1)))
	if err != nil || string(readyMessage) != PrivateRootReady {
		return errors.New("fixed private-root READY absent or malformed")
	}
	if err := closePrivateRootFile(&readyRead); err != nil {
		return err
	}
	if err := grantWrite.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(grantWrite, PrivateRootGrant); err != nil {
		return err
	}
	if err := closePrivateRootFile(&grantWrite); err != nil {
		return err
	}
	select {
	case err := <-waitDone:
		waited = true
		if err != nil {
			return fmt.Errorf("private-root child exit: %w", err)
		}
	case <-time.After(25 * time.Second):
		return errors.New("private-root child lifetime exceeded")
	}
	out, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	want := fmt.Sprintf("DCAX_PRIVATE_ROOT_STATIC_EXEC_PASS uid=%d gid=%d root_ro=true tmp_rw=true devices=true caps_zero=true\n", os.Getuid(), os.Getgid())
	if overflow || stderrOverflow || diagnostics != "" || strings.Count(out, want) != 1 || !strings.Contains(out, "--- PASS: TestPrivateRootStaticExecChild") || !strings.Contains(out, "\nPASS\n") {
		return errors.New("fixed private-root proof or test pass inventory differs")
	}
	fmt.Println("DCAX_PRIVATE_ROOT_CUSTODY pidfd=true namespace_init_reaped=true fixed_grant=true")
	return nil
}

// TestPrivateTmpfsRootProbe is a manually dispatched, trusted filesystem
// compatibility experiment. It does not run a peer, hook, model or agent and
// is not AXIS production or vendor runtime qualification.
func TestPrivateTmpfsRootProbe(t *testing.T) {
	if os.Getpid() == 1 {
		if err := privateRootChild(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := privateRootParent(); err != nil {
		t.Fatal(err)
	}
}

// This fixed static self reexec is the only workload in the compatibility
// probe. It checks the actual helper result after exec, without a peer/agent.
func TestPrivateRootStaticExecChild(t *testing.T) {
	if os.Getpid() != 1 || os.Getuid() <= 0 || verifyCaps(false) != nil {
		t.Fatal("private static exec lost PID/credential/capability custody")
	}
	var rootFS, tmpFS, devFS, procFS unix.Statfs_t
	if unix.Statfs("/", &rootFS) != nil || unix.Statfs("/tmp", &tmpFS) != nil ||
		unix.Statfs("/dev", &devFS) != nil || unix.Statfs("/proc", &procFS) != nil ||
		rootFS.Type != unix.TMPFS_MAGIC || tmpFS.Type != unix.TMPFS_MAGIC ||
		devFS.Type != unix.TMPFS_MAGIC || procFS.Type != unix.PROC_SUPER_MAGIC ||
		uint64(rootFS.Flags)&uint64(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV) != uint64(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV) ||
		uint64(rootFS.Flags)&uint64(unix.ST_NOEXEC) != 0 ||
		uint64(tmpFS.Flags)&uint64(unix.ST_RDONLY|unix.ST_NOEXEC) != uint64(unix.ST_NOEXEC) {
		t.Fatal("private static exec root/tmp/proc flags differ")
	}
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal("private static exec cannot open real null device")
	}
	if n, err := null.Write([]byte{1}); err != nil || n != 1 {
		t.Fatal("private static exec null device write differs")
	}
	if err := null.Close(); err != nil {
		t.Fatal(err)
	}
	temp, err := os.CreateTemp("/tmp", "fixed-private-root-")
	if err != nil {
		t.Fatal("private static exec tmp write refused")
	}
	if err := errors.Join(temp.Close(), os.Remove(temp.Name())); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	self, err := io.ReadAll(io.LimitReader(opened, privateRootImageBudget/3+1))
	closeErr := opened.Close()
	if err != nil || closeErr != nil || len(self) < 64 || int64(len(self)) > privateRootImageBudget/3 {
		t.Fatal("fixed static reexec image unavailable")
	}
	want := sha256.Sum256(self)
	for _, leaf := range [3]string{"peer", "bubblewrap", "payload"} {
		data, err := os.ReadFile("/run/axis/images/" + leaf)
		if err != nil || len(data) != len(self) || sha256.Sum256(data) != want {
			t.Fatal("private root typed runtime copy differs")
		}
	}
	fmt.Printf("DCAX_PRIVATE_ROOT_STATIC_EXEC_PASS uid=%d gid=%d root_ro=true tmp_rw=true devices=true caps_zero=true\n", os.Getuid(), os.Getgid())
}
